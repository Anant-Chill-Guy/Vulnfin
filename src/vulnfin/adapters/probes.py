from __future__ import annotations

import asyncio
from http.cookies import SimpleCookie
import re
import ssl
import uuid
import warnings
import xml.etree.ElementTree as ET

from ..core.findings import endpoint, identify, ip, match_advisories, text


PROTOCOLS = ('auto', 'http', 'https', 'tls', 'ssh', 'ftp', 'smtp', 'rtsp', 'redis', 'mqtt')
HINTS = {21: 'ftp', 22: 'ssh', 25: 'smtp', 80: 'http', 443: 'https', 554: 'rtsp',
         1883: 'mqtt', 6379: 'redis', 8000: 'http', 8080: 'http', 8443: 'https'}


def server_name(value):
    if value is None:
        return None
    if len(value) > 253 or any(not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label) for label in value.rstrip('.').split('.')):
        raise ValueError('Use a DNS name for --server-name')
    return value


def request_path(value):
    if not value.startswith('/') or value.startswith('//') or len(value) > 2048 or any(ord(c) < 33 or ord(c) > 126 for c in value) or '#' in value:
        raise ValueError('Use an ASCII path beginning with /, without spaces or a fragment')
    return value


async def close(writer):
    if writer is not None:
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), 1)
        except (OSError, asyncio.TimeoutError):
            pass


def tls_context(verified=False):
    if verified:
        return ssl.create_default_context()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


async def connection(host, port, timeout, context=None, name=None):
    return await asyncio.wait_for(asyncio.open_connection(host, port, ssl=context,
        **({'server_hostname': name or host, 'ssl_handshake_timeout': timeout} if context else {})), timeout)


async def exchange(host, port, timeout, request=None, size=16384, delimiter=None):
    reader, writer = await connection(host, port, timeout)
    try:
        if request:
            writer.write(request)
            await writer.drain()
        raw = await reader.readuntil(delimiter) if delimiter else await reader.read(size)
        if len(raw) > size:
            raise ValueError('Protocol reply exceeds its read limit')
        return raw
    finally:
        await close(writer)


async def http_request(host, port, timeout, *, secure=False, name=None, path='/', method='GET', body=b'', content_type=None, origin='https://vulnfin.invalid'):
    request_path(path)
    hostname = name or ('[' + host + ']' if ':' in host else host)
    authority = hostname + (':' + str(port) if port != (443 if secure else 80) else '')
    headers = [f'{method} {path} HTTP/1.1', 'Host: ' + authority, 'User-Agent: Vulnfin',
               'Accept: */*', 'Accept-Encoding: identity', 'Connection: close']
    if origin is not None:
        if not re.fullmatch(r'https://[A-Za-z0-9.-]+', origin):
            raise ValueError('Invalid probe origin')
        headers.append('Origin: ' + origin)
    if body:
        headers += ['Content-Type: ' + content_type, 'Content-Length: ' + str(len(body))]
    reader, writer = await connection(host, port, timeout, tls_context() if secure else None, name)
    try:
        writer.write(('\r\n'.join(headers) + '\r\n\r\n').encode('ascii') + body)
        await writer.drain()
        for _ in range(4):
            raw = await reader.readuntil(b'\r\n\r\n')
            if len(raw) > 32768:
                raise ValueError('HTTP headers exceed 32 KiB')
            lines = raw.decode('iso-8859-1').split('\r\n')
            status = re.fullmatch(r'HTTP/1\.[01] ([0-9]{3})(?: .*)?', lines[0])
            if not status:
                raise ValueError('No HTTP/1.x response')
            code = int(status.group(1))
            if not 100 <= code < 200:
                break
        else:
            raise ValueError('Too many informational HTTP responses')
        parsed = {}
        for line in lines[1:]:
            if not line:
                continue
            if ':' not in line:
                raise ValueError('Malformed HTTP header')
            key, value = line.split(':', 1)
            parsed.setdefault(key.lower(), []).append(value.strip())
        content = bytearray()
        complete = False
        limit = 65536
        if code in (204, 304) or method == 'HEAD':
            complete = True
        elif any('chunked' in v.lower() for v in parsed.get('transfer-encoding', [])):
            for _ in range(8192):
                line = await reader.readuntil(b'\r\n')
                if len(line) > 1024:
                    raise ValueError('Oversized HTTP chunk header')
                size = int(line.split(b';', 1)[0], 16)
                if size == 0:
                    complete = True
                    break
                take = min(size, limit - len(content))
                content.extend(await reader.readexactly(take))
                if len(content) >= limit:
                    break
                if await reader.readexactly(2) != b'\r\n':
                    raise ValueError('Malformed HTTP chunk')
        elif parsed.get('content-length'):
            if len(set(parsed['content-length'])) != 1:
                raise ValueError('Conflicting HTTP Content-Length headers')
            size = int(parsed['content-length'][0])
            if size < 0:
                raise ValueError('Invalid HTTP Content-Length')
            content.extend(await reader.readexactly(min(size, limit)))
            complete = size <= limit
        else:
            while len(content) < limit:
                chunk = await reader.read(min(8192, limit - len(content)))
                if not chunk:
                    complete = True
                    break
                content.extend(chunk)
        encoded = any(v.lower() not in ('identity', '') for v in parsed.get('content-encoding', []))
        return {'status': code, 'headers': parsed, 'body': bytes(content) if not encoded else b'',
                'body_complete': complete, 'body_encoded': encoded}
    finally:
        await close(writer)


async def tls_probe(report, target, timeout, name, source):
    host, port = target['address'], target['port']
    writer = None
    try:
        _, writer = await connection(host, port, timeout, tls_context(True), name)
        obj = writer.get_extra_info('ssl_object')
        cert = obj.getpeercert()
        report.check('tls.certificate', target, 'completed',
            'System trust and identity validation succeeded for ' + (name or host) + '; expires ' + str(cert.get('notAfter')), source)
    except ssl.SSLCertVerificationError as error:
        report.add('tls.configuration', target, 'TLS certificate validation failed', 'low', 'high',
            ['Validation identity: ' + (name or host), text(error.verify_message)],
            'This client could not validate the certificate for the supplied identity using its system trust store.',
            'Confirm the intended DNS name and trust policy; private CAs and IP-only checks need context.', state='potential', source=source)
        report.check('tls.certificate', target, 'observed', text(error.verify_message), source)
    finally:
        await close(writer)
    writer = None
    try:
        _, writer = await connection(host, port, timeout, tls_context(), name)
        obj = writer.get_extra_info('ssl_object')
        cipher = obj.cipher()
        report.check('tls.negotiation', target, 'observed', str(obj.version()) + ' / ' + str(cipher[0] if cipher else 'unknown cipher'), source)
    finally:
        await close(writer)
    for version, label in ((ssl.TLSVersion.TLSv1, 'TLS 1.0'), (ssl.TLSVersion.TLSv1_1, 'TLS 1.1')):
        writer = None
        try:
            with warnings.catch_warnings():
                warnings.simplefilter('ignore', DeprecationWarning)
                context = tls_context()
                context.minimum_version = context.maximum_version = version
                context.set_ciphers('DEFAULT:@SECLEVEL=0')
            _, writer = await connection(host, port, timeout, context, name)
            report.add('tls.configuration', target, label + ' accepted', 'medium', 'high',
                ['A handshake constrained to ' + label + ' succeeded'],
                'The endpoint accepts a deprecated TLS protocol.', 'Confirm compatibility requirements before disabling the deprecated protocol.', source=source)
            report.check('tls.legacy', target, 'observed', label + ' negotiated', source)
        except (OSError, asyncio.TimeoutError, ValueError) as error:
            rejected = isinstance(error, ssl.SSLError) and 'ALERT_PROTOCOL_VERSION' in str(error)
            report.check('tls.legacy', target, 'completed' if rejected else 'inconclusive',
                label + (' rejected with a protocol-version alert.' if rejected else ' not negotiated: ' + text(error) + '; this does not prove server-side rejection.'), source)
        finally:
            await close(writer)


def http_analysis(report, target, response, secure, source):
    headers, body, code = response['headers'], response['body'].decode('utf-8', 'replace'), response['status']
    joined = lambda key: ', '.join(headers.get(key, []))
    target['service'] = 'HTTPS' if secure else 'HTTP'
    products = identify(joined('server') + ' ' + joined('x-powered-by'))
    if products:
        target.update(product=products[0]['product'], product_version=products[0]['version'])
    report.check('http.response', target, 'observed', 'HTTP status ' + str(code) + '; Server: ' + text(joined('server') or 'not supplied'), source)
    if not secure and re.search(r'\bBasic\b', joined('www-authenticate'), re.I):
        report.add('http.configuration', target, 'Basic authentication offered over HTTP', 'medium', 'high',
            ['Plain HTTP response advertises Basic authentication'], 'Submitted credentials would lack TLS protection on this connection.',
            'Check whether clients can use a mandatory HTTPS endpoint before authenticating.', source=source)
    if joined('access-control-allow-origin') == 'https://vulnfin.invalid' and joined('access-control-allow-credentials').lower() == 'true':
        report.add('http.configuration', target, 'Credentialed CORS accepts the probe origin', 'medium', 'medium',
            ['Access-Control-Allow-Origin matched the supplied external origin', 'Access-Control-Allow-Credentials: true'],
            'The response permits this origin with credentials; sensitive response access has not been established.',
            'Verify origin policy and whether an authenticated browser can read sensitive content.', state='potential', source=source)
    for value in headers.get('set-cookie', []):
        cookies = SimpleCookie()
        try:
            cookies.load(value)
        except Exception:
            continue
        for name, morsel in cookies.items():
            missing = []
            if secure and not morsel['secure']:
                missing.append('Secure')
            if not morsel['httponly']:
                missing.append('HttpOnly')
            if missing:
                report.add('http.configuration', target, 'Cookie protection needs review: ' + text(name, 80), 'low', 'high',
                    ['Missing attributes: ' + ', '.join(missing), 'Cookie values omitted'],
                    'The cookie lacks these attributes; whether it carries authentication or sensitive state is unknown.',
                    'Identify the cookie purpose and required browser protection.', state='potential', source=source)
    html = 'text/html' in joined('content-type').lower()
    if html and 200 <= code < 300:
        absent = [key for key in ('content-security-policy', 'x-content-type-options') if not joined(key)]
        if secure and not joined('strict-transport-security'):
            absent.append('strict-transport-security')
        if absent:
            report.add('http.configuration', target, 'Browser security headers need review', 'info', 'high',
                ['Absent on this HTML response: ' + ', '.join(absent)],
                'These protections are not advertised on this response. Exploitability depends on application behaviour.',
                'Review application content, embedding requirements and HTTPS deployment.', state='potential', source=source)
    if 200 <= code < 300 and re.search(r'<title>\s*(?:Index of|Directory listing for)\s', body, re.I) and re.search(r'href\s*=', body, re.I):
        report.add('http.exposure', target, 'Directory listing returned', 'low', 'high',
            ['Directory-listing title and links received without supplied credentials'],
            'Directory contents are listed; whether those files should be public needs confirmation.',
            'Review the listed directory and its intended access policy.', state='potential', source=source)
    signatures = ('Traceback (most recent call last):', 'Fatal error:', 'phpinfo()')
    matched = [marker for marker in signatures if marker in body]
    if matched:
        report.add('http.exposure', target, 'Diagnostic output needs review', 'low', 'medium',
            ['Response contains diagnostic markers: ' + ', '.join(matched)],
            'The response may expose implementation details; marker matches can also occur in ordinary content.',
            'Inspect the response context and confirm unintended disclosure.', state='potential', source=source)
    if not response['body_complete'] or response['body_encoded']:
        report.check('http.body', target, 'inconclusive', 'Body was bounded at 64 KiB or encoded; body checks have limited coverage.', source)
    return products


async def web_probe(report, target, timeout, name, secure, path, source, advisory_rows):
    target = {**target, 'scheme': 'https' if secure else 'http', 'path': path,
              'service': 'HTTPS' if secure else 'HTTP'}
    response = await asyncio.wait_for(http_request(target['address'], target['port'], timeout, secure=secure, name=name, path=path), timeout * 2)
    products = http_analysis(report, target, response, secure, source)
    match_advisories(report, target, products, advisory_rows, source)
    try:
        git_path = path.rstrip('/') + '/.git/HEAD'
        git = await asyncio.wait_for(http_request(target['address'], target['port'], timeout, secure=secure, name=name, path=git_path), timeout * 2)
        body = git['body'].strip()
        if git['status'] == 200 and git['body_complete'] and re.fullmatch(rb'(?:ref: refs/[A-Za-z0-9_./-]+|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})', body):
            report.add('http.exposure', {**target, 'path': git_path}, 'Git HEAD metadata is publicly readable', 'medium', 'high',
                ['GET ' + git_path + ' returned a Git HEAD-shaped response without credentials'],
                'Repository metadata is exposed. Access to source files or secrets has not been tested.',
                'Confirm the response is repository metadata and review web-server access rules.', state='potential', source=source)
            report.check('http.git', target, 'observed', 'Git HEAD-shaped response', source)
        else:
            report.check('http.git', target, 'completed', 'No Git HEAD signature in this response; other paths were not tested.', source)
    except (OSError, asyncio.TimeoutError, ValueError, asyncio.IncompleteReadError, asyncio.LimitOverrunError) as error:
        report.check('http.git', target, 'inconclusive', text(error), source)


async def line_reply(reader):
    first = await reader.readuntil(b'\n')
    if len(first) > 4096:
        raise ValueError('Protocol greeting too long')
    result = bytearray(first)
    if len(first) >= 4 and first[:3].isdigit() and first[3:4] == b'-':
        for _ in range(64):
            line = await reader.readuntil(b'\n')
            result.extend(line)
            if len(result) > 16384:
                raise ValueError('Protocol reply exceeds 16 KiB')
            if line.startswith(first[:3] + b' '):
                return bytes(result)
        raise ValueError('Protocol reply has too many lines')
    return bytes(result)


async def text_probe(report, target, timeout, protocol, source, advisory_rows):
    host, port = target['address'], target['port']
    if protocol in ('ftp', 'smtp'):
        reader, writer = await connection(host, port, timeout)
        try:
            greeting = await line_reply(reader)
            if not greeting.startswith(b'220'):
                raise ValueError('No expected ' + protocol.upper() + ' greeting')
            writer.write(b'FEAT\r\n' if protocol == 'ftp' else b'EHLO vulnfin.invalid\r\n')
            await writer.drain()
            reply = await line_reply(reader)
            expected = b'211' if protocol == 'ftp' else b'250'
            report.check(protocol + '.greeting', target, 'observed', text(greeting.decode('utf-8', 'replace')), source)
            match_advisories(report, target, identify(greeting.decode('utf-8', 'replace')), advisory_rows, source)
            if not reply.startswith(expected):
                report.check(protocol + '.transport', target, 'inconclusive', 'Capability command was not accepted.', source)
                return
            upper = reply.upper()
            tls = bool(re.search(rb'\bAUTH\s+TLS\b', upper)) if protocol == 'ftp' else b'STARTTLS' in upper
            report.check(protocol + '.transport', target, 'observed', 'TLS upgrade advertised: ' + str(tls) + '; no login attempted.', source)
            if protocol == 'smtp' and re.search(rb'\bAUTH\b[^\r\n]*\b(?:PLAIN|LOGIN)\b', upper):
                report.add('smtp.transport', target, 'Password authentication advertised before TLS', 'low', 'medium',
                    ['EHLO before STARTTLS advertises AUTH PLAIN or LOGIN'],
                    'These authentication mechanisms are advertised on a plaintext connection; the server may still reject their use.',
                    'Verify TLS enforcement using a controlled test account.', state='potential', source=source)
            if not tls:
                report.add(protocol + '.transport', target, 'TLS upgrade not advertised', 'low', 'medium',
                    [protocol.upper() + ' capability reply did not advertise a TLS upgrade'],
                    'This capability response does not offer encrypted transport; alternate secure endpoints may exist.',
                    'Check the intended secure endpoint and whether clients send sensitive data here.', state='potential', source=source)
        finally:
            await close(writer)
    elif protocol == 'ssh':
        reader, writer = await connection(host, port, timeout)
        line = None
        try:
            total = 0
            for _ in range(16):
                candidate = await reader.readuntil(b'\n')
                total += len(candidate)
                if total > 8192:
                    raise ValueError('SSH identification exceeds 8 KiB')
                if candidate.startswith(b'SSH-'):
                    line = candidate.rstrip(b'\r\n')
                    break
        finally:
            await close(writer)
        if not line or not re.match(rb'SSH-(?:1\.\d+|2\.0)-', line):
            raise ValueError('No SSH identification received')
        banner = line.decode('ascii', 'replace')
        report.check('ssh.protocol', target, 'observed', banner, source)
        match_advisories(report, target, identify(banner), advisory_rows, source)
        if line.startswith(b'SSH-1.'):
            report.add('ssh.protocol', target, 'SSH 1 compatibility advertised', 'medium', 'high', [banner],
                'The identification advertises SSH 1 compatibility, including possible dual-protocol support.',
                'Verify protocol configuration and remove SSH 1 compatibility.', state='potential', source=source)
    elif protocol == 'rtsp':
        authority = '[' + host + ']' if ':' in host else host
        raw = await exchange(host, port, timeout, f'OPTIONS rtsp://{authority}:{port}/ RTSP/1.0\r\nCSeq: 1\r\n\r\n'.encode(), delimiter=b'\r\n\r\n')
        if not raw.startswith(b'RTSP/1.0 '):
            raise ValueError('No RTSP response')
        first = raw.split(b'\r\n', 1)[0].decode('ascii', 'replace')
        report.check('rtsp.methods', target, 'observed', first + '; OPTIONS access does not establish stream access.', source)
    elif protocol == 'redis':
        raw = await exchange(host, port, timeout, b'*1\r\n$4\r\nPING\r\n', size=1024, delimiter=b'\r\n')
        if raw.startswith(b'+PONG\r\n'):
            report.add('redis.access', target, 'Redis PING accepted without supplied credentials', 'info', 'high', ['RESP PONG response'],
                'PING is permitted on this connection. Data commands may have different ACL requirements.',
                'Review network exposure and Redis ACL policy without assuming data access.', state='potential', source=source)
            report.check('redis.access', target, 'observed', 'PING accepted; no data commands sent.', source)
        elif raw.startswith((b'-NOAUTH', b'-NOPERM')):
            report.check('redis.access', target, 'completed', 'PING requires authentication or permission.', source)
        else:
            raise ValueError('No recognized Redis PING response')
    elif protocol == 'mqtt':
        client = ('vf-' + uuid.uuid4().hex[:12]).encode()
        payload = b'\x00\x04MQTT\x04\x02\x00\x0a' + len(client).to_bytes(2, 'big') + client
        reader, writer = await connection(host, port, timeout)
        try:
            writer.write(b'\x10' + bytes([len(payload)]) + payload)
            await writer.drain()
            raw = await reader.readexactly(4)
            if raw[:2] != b'\x20\x02' or raw[2] not in (0, 1) or raw[3] > 5:
                raise ValueError('No MQTT 3.1.1 CONNACK')
            if raw[3] == 0:
                report.add('mqtt.access', target, 'MQTT connection accepted without supplied credentials', 'info', 'high', ['MQTT CONNACK return code 0; clean session'],
                    'An anonymous connection was accepted. Topic read/write permissions were not tested.',
                    'Review intended anonymous access and topic ACLs.', state='potential', source=source)
                writer.write(b'\xe0\x00')
                await writer.drain()
            report.check('mqtt.access', target, 'observed', 'CONNACK return code ' + str(raw[3]) + '; no subscriptions or publishes.', source)
        finally:
            await close(writer)


async def assess_endpoint(report, host, port, timeout, *, protocol='auto', name=None, path='/', advisory_rows=(), progress=None):
    target = endpoint(ip(host), port)
    if name:
        target.update(server_name=name, name=name, name_source='Supplied DNS name')
    source = 'live:' + host + ':' + str(port)
    selected = HINTS.get(port) if protocol == 'auto' else protocol
    if progress:
        progress('Checking ' + host + ':' + str(port) + ' · ' + (selected or 'identify'))
    try:
        if selected is None:
            observed_bytes = False
            try:
                reader, writer = await connection(host, port, timeout)
                report.check('service.connection', target, 'observed', 'TCP connection accepted.', source)
                try:
                    captured = bytearray()
                    deadline = asyncio.get_running_loop().time() + timeout
                    while len(captured) < 8192 and b'\n' not in captured:
                        remaining = deadline - asyncio.get_running_loop().time()
                        if remaining <= 0:
                            break
                        try:
                            chunk = await asyncio.wait_for(reader.read(8192 - len(captured)), remaining)
                        except asyncio.TimeoutError:
                            break
                        if not chunk:
                            break
                        captured.extend(chunk)
                    raw = bytes(captured)
                except asyncio.TimeoutError:
                    raw = b''
                finally:
                    await close(writer)
                observed_bytes = bool(raw)
            except asyncio.TimeoutError:
                report.check('service.connection', target, 'inconclusive', 'No response; service not identified.', source)
                return
            if raw.startswith(b'SSH-'):
                selected = 'ssh'
            else:
                try:
                    response = await asyncio.wait_for(http_request(host, port, timeout, name=name, path=path), timeout * 2)
                    http_analysis(report, target, response, False, source)
                    selected = 'http'
                except (OSError, ValueError, asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError) as error:
                    report.check('service.identification', target, 'unsupported' if observed_bytes else 'inconclusive',
                        'Received an unrecognized service response; use --protocol if known.' if observed_bytes else
                        'Connection accepted but no supported protocol response was received; service not identified.', source)
                    return
        target['service'] = selected.upper() if selected else None
        report.remember(target)
        if selected in ('https', 'tls'):
            try:
                await asyncio.wait_for(tls_probe(report, target, timeout, name, source), timeout * 6 + 4)
            except (OSError, ValueError, asyncio.TimeoutError) as error:
                report.check('tls.configuration', target, 'inconclusive', text(error), source)
            if selected == 'https':
                await web_probe(report, target, timeout, name, True, path, source, advisory_rows)
        elif selected == 'http':
            await web_probe(report, target, timeout, name, False, path, source, advisory_rows)
        else:
            await asyncio.wait_for(text_probe(report, target, timeout, selected, source, advisory_rows), timeout * 3)
    except ConnectionRefusedError:
        report.check('service.connection', target, 'closed', 'TCP connection refused; no assessment performed.', source)
    except (OSError, ValueError, asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError) as error:
        report.check('service.' + (selected or 'identification'), target, 'inconclusive', text(error) or 'Timed out', source)


async def onvif_probe(report, host, port, timeout, *, secure=False, name=None, path='/onvif/device_service'):
    target = {**endpoint(ip(host), port), 'scheme': 'https' if secure else 'http', 'path': path, 'service': 'ONVIF'}
    if name:
        target['server_name'] = name
    if name:
        target.update(name=name, name_source='Supplied DNS name')
    report.remember(target)
    source = 'live:onvif:' + host + ':' + str(port) + path
    body = (b'<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>'
            b'<GetDeviceInformation xmlns="http://www.onvif.org/ver10/device/wsdl"/>'
            b'</s:Body></s:Envelope>')
    try:
        response = await asyncio.wait_for(http_request(host, port, timeout, secure=secure, name=name, path=path,
            method='POST', body=body, content_type='application/soap+xml; charset=utf-8; action="http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation"'), timeout * 2)
        if response['status'] in (401, 403):
            report.check('onvif.information', target, 'completed', 'HTTP authentication or access control rejected the request.', source)
            return
        raw = response['body']
        if not response['body_complete'] or response['body_encoded']:
            raise ValueError('SOAP response incomplete or encoded')
        if b'<!DOCTYPE' in raw.upper() or b'<!ENTITY' in raw.upper():
            raise ValueError('SOAP response contains prohibited XML declarations')
        root = ET.fromstring(raw)
        namespace = '{http://www.onvif.org/ver10/device/wsdl}'
        match = next((e for e in root.iter() if e.tag == namespace + 'GetDeviceInformationResponse'), None)
        if response['status'] == 200 and match is not None:
            values = {e.tag.rsplit('}', 1)[-1]: text(e.text) for e in match.iter()
                      if e.tag.rsplit('}', 1)[-1] in ('Manufacturer', 'Model', 'FirmwareVersion')}
            if not values or not any(values.values()):
                raise ValueError('ONVIF response has no expected device-information values')
            target['product'] = ' '.join(values.get(k, '') for k in ('Manufacturer', 'Model')).strip()
            report.add('onvif.information', target, 'ONVIF device information returned without supplied credentials', 'low', 'high',
                [key + ': ' + value for key, value in values.items()],
                'The endpoint returns device metadata. Whether anonymous metadata access violates policy is unverified.',
                'Confirm the intended access policy; this does not establish stream or administrative access.', state='potential', source=source)
            report.check('onvif.information', target, 'observed', 'Valid GetDeviceInformationResponse received.', source)
        else:
            report.check('onvif.information', target, 'inconclusive', 'No successful device-information response; authentication enforcement is not established.', source)
    except (OSError, ValueError, asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError, ET.ParseError) as error:
        report.check('onvif.information', target, 'inconclusive', text(error) or 'Timed out', source)
