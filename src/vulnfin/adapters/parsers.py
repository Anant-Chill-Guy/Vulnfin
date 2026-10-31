from __future__ import annotations

import re

from ..core.assessment import wifi_observations


MAC = r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}'


def frequency_channel(mhz):
    if mhz == 2484: return 14
    if 2412 <= mhz <= 2472: return int((mhz - 2407) / 5)
    if 5000 <= mhz < 5900: return int((mhz - 5000) / 5)
    if mhz == 5935: return 2
    if 5955 <= mhz <= 7115: return int((mhz - 5950) / 5)
    return None


def band_name(mhz):
    if 2400 <= mhz < 2500: return '2.4 GHz'
    if 4900 <= mhz < 5925: return '5 GHz'
    if 5925 <= mhz <= 7125: return '6 GHz'
    if 57000 <= mhz <= 71000: return '60 GHz'
    return 'other'


def mac_properties(mac):
    first = int(mac.split(':')[0], 16)
    return {'locally_administered': bool(first & 2), 'multicast': bool(first & 1),
            'vendor': None, 'vendor_note': 'No manufacturer is inferred without an OUI database.'}


def indentation_tree(text):
    roots = []
    stack = [(-1, roots)]
    for line in text.splitlines():
        if not line.strip(): continue
        expanded = line.expandtabs(8)
        indent = len(expanded) - len(expanded.lstrip())
        while len(stack) > 1 and indent <= stack[-1][0]: stack.pop()
        node = {'text': line.strip(), 'children': []}
        stack[-1][1].append(node)
        stack.append((indent, node['children']))
    return roots


def parse_iw_devices(text):
    radios, current, interface = [], None, None
    for line in text.splitlines():
        value = line.strip()
        if value.startswith('phy#'):
            current = {'phy': 'phy' + value[4:], 'interfaces': []}
            radios.append(current)
            interface = None
        elif value.startswith('Interface ') and current is not None:
            interface = {'name': value.partition(' ')[2]}
            current['interfaces'].append(interface)
        elif interface is not None:
            if match := re.match(r'(ifindex|wdev|addr|type|ssid|wiphy)\s+(.+)', value):
                interface[match[1]] = match[2]
            elif value.startswith('channel '): interface['channel_description'] = value
            elif value.startswith('txpower '): interface['txpower_description'] = value
    return radios


def parse_wiphy(text):
    radios = []
    for block in re.split(r'(?=^Wiphy )', text, flags=re.M):
        if not block.startswith('Wiphy '): continue
        lines = block.splitlines()
        radio = {'phy': lines[0].split()[1], 'modes': [], 'ciphers': [], 'channels': [],
                 'interface_combinations': [], 'features': []}
        section = None
        for line in lines[1:]:
            s = line.strip()
            if s == 'Supported interface modes:': section = 'modes'; continue
            if s == 'Supported Ciphers:': section = 'ciphers'; continue
            if s == 'valid interface combinations:': section = 'interface_combinations'; continue
            if s == 'Supported extended features:': section = 'features'; continue
            if section and s.startswith('* '): radio[section].append(s[2:])
            elif section == 'interface_combinations' and s.startswith(('total ', '#{')):
                radio[section].append(s)
            else: section = None
            if 'interface combinations are not supported' in s:
                radio['interface_combinations_advertised'] = False
            if match := re.match(r'\*\s+(\d+(?:\.\d+)?) MHz \[(\d+)\](.*)', s):
                freq, chan, tail = float(match[1]), int(match[2]), match[3]
                power = re.search(r'\(([\d.]+) dBm\)', tail)
                radio['channels'].append({'frequency_mhz': freq, 'channel': chan,
                    'band': band_name(freq), 'max_txpower_dbm': float(power[1]) if power else None,
                    'disabled': 'disabled' in tail, 'no_initiate_radiation': 'no IR' in tail,
                    'radar_detection': 'radar detection' in tail, 'flags_raw': tail.strip()})
        radio['bands'] = sorted({c['band'] for c in radio['channels']})
        radio['raw'] = block
        radios.append(radio)
    return radios


def parse_security(block, privacy):
    sections = []
    for match in re.finditer(r'^([ \t]*)(RSN|WPA):[ \t]*([^\r\n]*)\r?$', block, re.M):
        indent = len(match[1].expandtabs(8))
        chunk = [match[3].strip()] if match[3].strip() else []
        for line in block[match.end():].splitlines():
            if not line.strip(): continue
            current = len(line.expandtabs(8)) - len(line.lstrip().expandtabs(8))
            if current <= indent: break
            chunk.append(line.strip())
        raw = '\n'.join(chunk)
        def extract(label):
            found = re.search(r'^\*?[ \t]*' + re.escape(label) + r':[ \t]*([^\r\n]*)$', raw, re.M)
            return found[1].strip() if found else None
        capabilities = extract('Capabilities')
        bits = re.search(r'\(0x([0-9a-fA-F]+)\)', capabilities or '')
        cap = int(bits[1], 16) if bits else None
        sections.append({'element': match[2], 'group_cipher': extract('Group cipher'),
            'pairwise_ciphers_raw': extract('Pairwise ciphers'),
            'authentication_suites_raw': extract('Authentication suites'),
            'capabilities_raw': capabilities, 'pmf_capable': bool(cap & 0x80) if cap is not None else None,
            'pmf_required': bool(cap & 0x40) if cap is not None else None,
            'raw': raw})
    suites = ' '.join(s.get('authentication_suites_raw') or '' for s in sections)
    rsn = any(s['element'] == 'RSN' for s in sections)
    labels = []
    if 'OWE' in suites: labels.append('OWE advertised')
    if 'SAE' in suites: labels.append('SAE advertised')
    if 'PSK' in suites: labels.append('PSK advertised')
    if 'IEEE 802.1X' in suites or '802.1X' in suites: labels.append('802.1X advertised')
    if not labels:
        if rsn: labels = ['RSN; inspect authentication suites']
        elif sections: labels = ['WPA vendor element']
        elif privacy: labels = ['Privacy bit; security type unresolved']
        elif privacy is None: labels = ['Security metadata unavailable']
        else: labels = ['No RSN/WPA element or privacy bit observed']
    return {'summary': ', '.join(labels), 'privacy_bit': privacy, 'elements': sections,
            'note': 'Advertisement only; authentication, cipher negotiation and vulnerability are not validated.'}


def parse_wifi_scan(text, interface, method):
    aps = []
    for block in re.split(r'(?=^BSS\s+)', text, flags=re.M):
        match = re.match(r'BSS\s+(' + MAC + r')\b([^\n]*)', block)
        if not match: continue
        ap = {'bssid': match[1].lower(), 'interface': interface, 'discovery_method': method,
              'associated_marker': 'associated' in match[2], 'ssid': None, 'hidden_or_empty_ssid': True,
              'frequency_mhz': None, 'channel': None, 'signal_dbm': None,
              'beacon_interval_tu': None, 'last_seen_ms_ago': None,
              'country_advertised': None, 'capability_raw': None,
              'supported_rates_raw': [], 'phy_elements_observed': [], 'raw': block.rstrip()}
        for line in block.splitlines()[1:]:
            value = line.strip()
            if value.startswith('SSID:'):
                ap['ssid'] = re.match(r'^\s*SSID: ?(.*)$', line)[1]
                ap['hidden_or_empty_ssid'] = not ap['ssid'] or '\\x00' in ap['ssid']
            elif m := re.match(r'freq:\s*(\d+(?:\.\d+)?)', value): ap['frequency_mhz'] = float(m[1])
            elif m := re.match(r'signal:\s*(-?[\d.]+)\s+dBm', value): ap['signal_dbm'] = float(m[1])
            elif m := re.match(r'beacon interval:\s*(\d+)', value): ap['beacon_interval_tu'] = int(m[1])
            elif m := re.match(r'last seen:\s*(\d+)\s*ms ago', value): ap['last_seen_ms_ago'] = int(m[1])
            elif value.startswith('Country:'): ap['country_advertised'] = value[8:].strip()
            elif value.startswith('capability:'): ap['capability_raw'] = value[11:].strip()
            elif value.startswith(('Supported rates:', 'Extended supported rates:')): ap['supported_rates_raw'].append(value)
            if value.startswith(('HT capabilities:', 'HT operation:', 'VHT capabilities:', 'VHT operation:',
                                 'HE capabilities:', 'HE operation:', 'EHT capabilities:', 'EHT operation:')):
                ap['phy_elements_observed'].append(value.rstrip(':'))
        if ap['frequency_mhz'] is not None:
            ap['channel'] = frequency_channel(ap['frequency_mhz'])
            ap['band'] = band_name(ap['frequency_mhz'])
        privacy = None if ap['capability_raw'] is None else 'Privacy' in ap['capability_raw']
        ap['security'] = parse_security(block, privacy)
        ap['address_properties'] = mac_properties(ap['bssid'])
        ap['information_elements_tree'] = indentation_tree('\n'.join(block.splitlines()[1:]))
        ap['ssid_representation'] = 'iw display text; escaped nonprintable bytes are retained, not decoded'
        ap['security_observations'] = wifi_observations(ap)
        aps.append(ap)
    return aps
