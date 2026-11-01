from __future__ import annotations

import re
import shutil
import xml.etree.ElementTree as ET

from .linux import Runner
from ..core.findings import endpoint, match_advisories, text

SCRIPTS = {22: 'ssh2-enum-algos', 445: 'smb2-security-mode', 3389: 'rdp-enum-encryption', 5900: 'vnc-info'}
NAMES = {'http': 'http', 'ssl/http': 'https', 'https': 'https', 'ssh': 'ssh', 'ftp': 'ftp',
         'smtp': 'smtp', 'rtsp': 'rtsp', 'redis': 'redis', 'mqtt': 'mqtt'}


def analyse_scripts(report, target, scripts, source):
    for script in scripts:
        identity = script.get('id')
        if identity not in SCRIPTS.values():
            continue
        output = script.get('output', '')
        if not output.strip() or re.search(r'(?i)(?:ERROR:|failed to execute|timed out)', output):
            report.check('nmap.' + identity, target, 'inconclusive', text(output or 'No script output', 2048), source)
            continue
        target['service'] = {'ssh2-enum-algos': 'SSH', 'smb2-security-mode': 'SMB', 'rdp-enum-encryption': 'RDP', 'vnc-info': 'VNC'}[identity]
        report.check('nmap.' + identity, target, 'observed', text(output, 4096), source)
        if identity == 'smb2-security-mode' and ('signing enabled but not required' in output.lower() or 'message signing disabled' in output.lower()):
            report.add('smb.signing', target, 'SMB signing is not required', 'medium', 'high', [text(output, 2048)],
                'The reported SMB dialect permits sessions without required signing. Relay feasibility depends on additional conditions.',
                'Verify signing policy, authentication paths and compensating controls.', state='potential', source=source)
        elif identity == 'rdp-enum-encryption':
            weak = re.findall(r'(?:40|56)-bit RC4:\s*SUCCESS', output)
            if weak:
                report.add('rdp.encryption', target, 'Legacy RDP encryption accepted', 'medium', 'high', weak,
                    'The service accepts the listed legacy encryption modes.',
                    'Review required RDP security layers, client compatibility and NLA policy.', state='potential', source=source)
        elif identity == 'vnc-info' and re.search(r'\bNone\s*\(1\)', output):
            report.add('vnc.authentication', target, 'VNC advertises None authentication', 'high', 'high', ['VNC security type None (1) reported'],
                'A no-authentication security type is offered; desktop access has not been exercised.',
                'Verify access policy and whether this option grants a session on the selected endpoint.', state='potential', source=source)
        elif identity == 'ssh2-enum-algos':
            weak = sorted({e.text.strip() for e in script.iter('elem') if e.text and e.text.strip() in
                {'diffie-hellman-group1-sha1', 'ssh-dss', 'arcfour', 'arcfour128', 'arcfour256', '3des-cbc'}})
            if weak:
                report.add('ssh.algorithms', target, 'Legacy SSH algorithms advertised', 'medium', 'high', weak,
                    'The server advertises these legacy algorithms; actual client selection was not tested.',
                    'Review the SSH algorithm policy and negotiated algorithms.', state='potential', source=source)


async def nmap_probe(report, host, port, advisory_rows=()):
    target = endpoint(host, port)
    source = 'live:nmap:' + host + ':' + str(port)
    if not shutil.which('nmap'):
        raise ValueError('nmap not found. Install nmap with the system package manager')
    argv = ['nmap', '-n', '-Pn', '-sT', '-sV', '--version-light', '--max-retries', '1',
            '--host-timeout', '45s', '--script-timeout', '10s', '-p', str(port), '-oX', '-']
    script = SCRIPTS.get(port)
    if script:
        argv += ['--script', script]
    if ':' in host:
        argv.append('-6')
    result = await Runner(limit=8*1024*1024).command([*argv, host], timeout=50)
    if result.status != 'OK' or result.truncated:
        report.check('nmap.identification', target, 'inconclusive', text(result.stderr or result.status), source)
        return None
    if b'<!ENTITY' in result.stdout.upper().encode():
        raise ValueError('Unexpected entity declaration in Nmap output')
    try:
        root = ET.fromstring(result.stdout)
    except ET.ParseError:
        report.check('nmap.identification', target, 'inconclusive', 'Nmap XML output is incomplete.', source)
        return None
    hostnode = next((h for h in root.findall('host') if any(a.get('addr') == host for a in h.findall('address'))), None)
    if hostnode is None:
        report.check('nmap.identification', target, 'inconclusive', 'No host result; the Nmap host timeout may have expired.', source)
        return None
    portnode = hostnode.find("ports/port[@portid='" + str(port) + "']")
    if portnode is None or portnode.find('state') is None:
        report.check('nmap.identification', target, 'inconclusive', 'No endpoint state returned.', source)
        return None
    state = portnode.find('state').get('state')
    if state != 'open':
        report.check('nmap.identification', target, 'closed' if state == 'closed' else 'inconclusive', 'Nmap state: ' + str(state), source)
        return None
    service = portnode.find('service')
    protocol = None
    if service is not None:
        fields = {k: service.get(k) for k in ('name', 'product', 'version', 'extrainfo', 'tunnel', 'method', 'conf') if service.get(k)}
        target.update(service=fields.get('name') if fields.get('method') == 'probed' else None,
                      product=fields.get('product'), product_version=fields.get('version'))
        report.check('nmap.identification', target, 'observed', '; '.join(k + ': ' + text(v) for k, v in fields.items()), source)
        if fields.get('method') == 'probed':
            protocol = NAMES.get(fields.get('name'))
            if fields.get('tunnel') == 'ssl':
                protocol = 'https' if protocol == 'http' else 'tls'
            aliases = {'openssh': 'openssh', 'apache httpd': 'apache_http_server', 'nginx': 'nginx', 'microsoft iis httpd': 'iis', 'vsftpd': 'vsftpd', 'proftpd': 'proftpd'}
            product = aliases.get(fields.get('product', '').casefold())
            if product and fields.get('version'):
                match_advisories(report, target, [{'product': product, 'version': fields['version']}], advisory_rows, source)
    scripts = [*portnode.findall('script'), *hostnode.findall('hostscript/script')]
    analyse_scripts(report, target, scripts, source)
    if script and not any(s.get('id') == script for s in scripts):
        report.check('nmap.' + script, target, 'inconclusive', 'Selected script returned no result; the check did not establish a pass.', source)
    return protocol
