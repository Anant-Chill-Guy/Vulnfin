from __future__ import annotations

import asyncio
import errno
import ipaddress
import socket
import ssl
import time
import uuid
from urllib.parse import urlsplit
import xml.etree.ElementTree as ET

from ..core.models import Manifest


PORTS = {21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns', 80: 'http', 443: 'https',
         445: 'smb', 554: 'rtsp', 1883: 'mqtt', 8000: 'http?', 8080: 'http?', 8443: 'https?'}


def addresses(value):
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError:
        raise ValueError('Use an IP address or CIDR range') from None
    if network.num_addresses > 256:
        raise ValueError('Choose at most 256 addresses per scan')
    if network.network_address.is_multicast or network.is_unspecified:
        raise ValueError('Choose unicast target addresses')
    return [str(host) for host in network.hosts()]


def port_list(value):
    found = set()
    try:
        for item in value.split(','):
            if '-' in item:
                low, high = map(int, item.split('-', 1))
                if high < low or high - low > 255:
                    raise ValueError()
                found.update(range(low, high + 1))
            else:
                found.add(int(item))
    except ValueError:
        raise ValueError('Use ports such as 22,80,443 or 8000-8010') from None
    if not found or len(found) > 256 or min(found) < 1 or max(found) > 65535:
        raise ValueError('Choose 1–256 ports within 1–65535')
    return sorted(found)


class ServiceDiscovery:
    manifest = Manifest('recon.services', 'TCP service discovery', 'network',
                        'Connect to explicit IP targets and inspect selected services.',
                        parameters=('target', 'ports', 'timeout', 'concurrency'))

    def prepare(self, params, config):
        params['hosts'] = addresses(params['target'])
        params['port_numbers'] = port_list(params.get('ports', '22,80,443,554,8000,8080,8443'))
        params['timeout'] = float(params.get('timeout', 1))
        params['concurrency'] = int(params.get('concurrency', 32))
        if not 0.1 <= params['timeout'] <= 10 or not 1 <= params['concurrency'] <= 128:
            raise ValueError('Timeout must be 0.1–10 seconds; concurrency must be 1–128')
        return params

    async def run(self, ctx, params):
        queue = asyncio.Queue()
        for host in params['hosts']:
            for port in params['port_numbers']:
                queue.put_nowait((host, port))
        opened, errors = [], {}
        checked, refused, unanswered = 0, 0, 0
        async def worker():
            nonlocal checked, refused, unanswered
            while not queue.empty():
                host, port = queue.get_nowait()
                writer = None
                try:
                    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), params['timeout'])
                    row = {'address': host, 'port': port, 'state': 'open', 'port_hint': PORTS.get(port),
                           'service': 'unknown', 'evidence': None}
                    try:
                        if port in (80, 8000, 8080):
                            writer.write(f'HEAD / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n'.encode())
                            await writer.drain()
                            response = await asyncio.wait_for(reader.read(4096), params['timeout'])
                            if response.startswith(b'HTTP/'):
                                row.update(service='http', evidence=response.split(b'\r\n\r\n')[0].decode('utf-8', 'replace'))
                        elif port == 554:
                            writer.write(f'OPTIONS rtsp://{host}/ RTSP/1.0\r\nCSeq: 1\r\n\r\n'.encode())
                            await writer.drain()
                            response = await asyncio.wait_for(reader.read(4096), params['timeout'])
                            if response.startswith(b'RTSP/'):
                                row.update(service='rtsp', evidence=response.decode('utf-8', 'replace'))
                        elif port in (21, 22, 23, 25):
                            response = await asyncio.wait_for(reader.read(1024), params['timeout'])
                            if response:
                                row['evidence'] = response.decode('utf-8', 'replace')
                                if response.startswith(b'SSH-'):
                                    row['service'] = 'ssh'
                        elif port in (443, 8443):
                            writer.close()
                            await asyncio.wait_for(writer.wait_closed(), 0.5)
                            writer = None
                            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                            context.check_hostname = False
                            context.verify_mode = ssl.CERT_NONE
                            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port, ssl=context), params['timeout'])
                            row.update(service='tls', evidence={'cipher': writer.get_extra_info('ssl_object').cipher(),
                                                               'certificate_verified': False})
                    except (OSError, asyncio.TimeoutError, ssl.SSLError):
                        pass
                    opened.append(row)
                except asyncio.TimeoutError:
                    unanswered += 1
                except OSError as error:
                    if error.errno == errno.ECONNREFUSED:
                        refused += 1
                    else:
                        unanswered += 1
                        key = str(error)
                        errors[key] = errors.get(key, 0) + 1
                finally:
                    checked += 1
                    if writer:
                        writer.close()
                        try:
                            await asyncio.wait_for(writer.wait_closed(), 0.5)
                        except (OSError, asyncio.TimeoutError):
                            pass
                    queue.task_done()
        workers = [asyncio.create_task(worker()) for _ in range(min(params['concurrency'], queue.qsize()))]
        try:
            await asyncio.gather(*workers)
        finally:
            for task in workers:
                task.cancel()
            await asyncio.gather(*workers, return_exceptions=True)
        rows = sorted(opened, key=lambda x: (ipaddress.ip_address(x['address']), x['port']))
        return ctx.observation(self.manifest.id, {'services': rows, 'checked': checked, 'refused': refused,
                                                 'unanswered': unanswered, 'errors': errors},
                               status='OBSERVED' if rows else 'EMPTY')


class CameraDiscovery:
    manifest = Manifest('recon.cameras', 'ONVIF discovery', 'network', 'Find ONVIF video-transmitter advertisements on one local interface.',
                        parameters=('address', 'duration'))

    def prepare(self, params, config):
        try:
            address = ipaddress.IPv4Address(params['address'])
        except ValueError:
            raise ValueError('Use the local IPv4 address of the interface to query') from None
        if address.is_multicast or address.is_unspecified:
            raise ValueError('Choose a local unicast IPv4 address')
        params['address'] = str(address)
        params['duration'] = float(params.get('duration', 5))
        if not 1 <= params['duration'] <= 30:
            raise ValueError('Duration must be 1–30 seconds')
        return params

    async def run(self, ctx, params):
        identity = 'uuid:' + str(uuid.uuid4())
        probe = (f'<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
                 'xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
                 'xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" '
                 'xmlns:dn="http://www.onvif.org/ver10/network/wsdl">'
                 f'<s:Header><a:MessageID>{identity}</a:MessageID>'
                 '<a:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To>'
                 '<a:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</a:Action></s:Header>'
                 '<s:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe></s:Body></s:Envelope>').encode()
        found = {}
        loop = asyncio.get_running_loop()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(params['address']))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
            sock.bind((params['address'], 0))
            sock.setblocking(False)
            start = time.monotonic()
            sent = -1
            while time.monotonic() - start < params['duration']:
                elapsed = time.monotonic() - start
                if sent < 0 or sent == 0 and elapsed > params['duration'] / 2:
                    await loop.sock_sendto(sock, probe, ('239.255.255.250', 3702))
                    sent += 1
                try:
                    raw, peer = await asyncio.wait_for(loop.sock_recvfrom(sock, 16384), min(0.3, params['duration'] - elapsed))
                except asyncio.TimeoutError:
                    continue
                if b'<!DOCTYPE' in raw.upper() or b'<!ENTITY' in raw.upper():
                    continue
                try:
                    tree = ET.fromstring(raw)
                except ET.ParseError:
                    continue
                related = [x.text for x in tree.iter() if x.tag.endswith('}RelatesTo')]
                if identity not in related:
                    continue
                for match in tree.iter():
                    if not match.tag.endswith('}ProbeMatch'):
                        continue
                    values = {x.tag.rsplit('}', 1)[-1]: (x.text or '').strip() for x in match.iter()}
                    endpoints = []
                    for url in values.get('XAddrs', '').split()[:8]:
                        try:
                            if len(url) <= 1024 and urlsplit(url).scheme in ('http', 'https'):
                                endpoints.append(url)
                        except ValueError:
                            continue
                    key = peer[0] + ':' + values.get('Address', '')
                    if len(found) < 256 or key in found:
                        found[key] = {'address': peer[0], 'endpoint_id': values.get('Address'), 'types': values.get('Types'),
                                      'scopes': values.get('Scopes'), 'urls': endpoints, 'source': 'onvif_probe_response'}
        return ctx.observation(self.manifest.id, {'devices': list(found.values()), 'local_address': params['address']},
                               status='OBSERVED' if found else 'EMPTY')


PLUGINS = (ServiceDiscovery, CameraDiscovery)
