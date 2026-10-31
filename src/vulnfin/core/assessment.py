from __future__ import annotations

import re


def wifi_observations(ap):
    security = ap.get('security') or {}
    elements = security.get('elements') or []
    results = []
    def add(code, title, priority, evidence, meaning, verify):
        results.append({'id': code, 'title': title, 'priority': priority,
            'category': 'advertised_configuration', 'confirmed_vulnerability': False,
            'evidence': evidence, 'meaning': meaning, 'verification': verify})
    if any(e.get('element') == 'WPA' for e in elements):
        add('wifi.legacy_wpa', 'Legacy WPA advertised', 3,
            ['WPA vendor security element present'],
            'The AP advertises legacy WPA compatibility. This does not prove a client negotiated it.',
            'Check the authorized AP configuration and client compatibility before disabling legacy modes.')
    cipher_fields = [str(e.get(k) or '') for e in elements
                     for k in ('group_cipher', 'pairwise_ciphers_raw')]
    legacy = sorted(set(re.findall(r'\b(?:TKIP|WEP(?:[- ]?(?:40|104))?)\b', ' '.join(cipher_fields), re.I)))
    if legacy:
        add('wifi.legacy_cipher', 'Legacy cipher advertised', 3,
            ['Cipher advertisement: ' + ', '.join(legacy)],
            'Legacy cipher support is a configuration weakness to review; negotiated traffic was not tested.',
            'Verify the AP cipher configuration and actual client negotiation; prefer current protected modes.')
    if security.get('privacy_bit') is False and ap.get('capability_raw') is not None and not elements:
        add('wifi.no_link_encryption', 'No link encryption advertised', 2,
            ['Privacy bit clear', 'No RSN or WPA security element parsed'],
            'The observed BSS does not advertise Wi-Fi link encryption. It may be an intentional guest network.',
            'Confirm the intended network policy. Captive portals and application TLS are separate from Wi-Fi link protection.')
    return results


def security_label(ap):
    sec = ap.get('security') or {}
    elems = sec.get('elements') or []
    suites = ' '.join(str(e.get('authentication_suites_raw') or '') for e in elems)
    if elems:
        auth = []
        for term, name in [('OWE', 'OWE'), ('SAE', 'SAE'), ('PSK', 'PSK'), ('802.1X', '802.1X')]:
            if term in suites: auth.append(name)
        protocols = '/'.join(dict.fromkeys(str(e.get('element')) for e in elems))
        ciphers = sorted(set(str(e.get('group_cipher')) for e in elems if e.get('group_cipher')))
        return protocols + ('-' + '/'.join(auth) if auth else '') + (' / ' + '+'.join(ciphers) if ciphers else '')
    if sec.get('privacy_bit') is False and ap.get('capability_raw') is not None:
        return 'No link encryption'
    return 'Unresolved'


def pmf_label(ap):
    elems = [e for e in (ap.get('security') or {}).get('elements', []) if e.get('element') == 'RSN']
    if not elems: return 'Unknown / not applicable'
    if any(e.get('pmf_required') is True for e in elems): return 'Required'
    if any(e.get('pmf_capable') is True for e in elems): return 'Capable'
    if all(e.get('pmf_capable') is False for e in elems): return 'Not advertised'
    return 'Unknown'
