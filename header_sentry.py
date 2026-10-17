"""Offline response-header checks; heuristic findings are not exploit proof."""
import argparse
import json
from pathlib import Path
import re
import sys

def parse(text):
    headers = {}
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        if number == 1 and line.startswith('HTTP/'):
            continue
        if ':' not in line or line[0].isspace():
            raise ValueError(f'invalid header at line {number}; supply one response block')
        name, value = line.split(':', 1)
        if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name):
            raise ValueError(f'invalid header name at line {number}')
        headers.setdefault(name.lower(), []).append(value.strip())
    return headers

def audit(text, https=False):
    headers = parse(text)
    findings = []
    def add(rule, severity, message):
        findings.append(dict(rule=rule, severity=severity, recommendation=message))
    def single(name):
        values = headers.get(name, [])
        if len(values) > 1:
            add('duplicate_' + name, 'review', 'Revise cabeçalhos duplicados e o comportamento do navegador.')
        return values[0] if values else ''
    csp = single('content-security-policy')
    directives = {}
    for piece in csp.split(';'):
        tokens = piece.split()
        if tokens:
            directives.setdefault(tokens[0].lower(), tokens[1:])
    if not csp:
        add('missing_csp', 'medium', 'Defina Content-Security-Policy adequada à aplicação; report-only não aplica restrições.')
    else:
        if 'default-src' not in directives:
            add('csp_no_default', 'review', 'Revise a ausência de default-src e as diretivas específicas.')
        script = directives.get('script-src', directives.get('default-src', []))
        if any(value in script for value in ["'unsafe-inline'", "'unsafe-eval'", '*']):
            add('csp_weak_script', 'medium', 'Restrinja fontes de scripts e considere nonces ou hashes.')
        if not directives.get('object-src') == ["'none'"]:
            add('csp_object', 'review', "Considere object-src 'none' quando objetos não forem necessários.")
    frame = single('x-frame-options').upper()
    ancestors = directives.get('frame-ancestors', [])
    if frame not in ('DENY', 'SAMEORIGIN') and (not ancestors or '*' in ancestors):
        add('framing', 'medium', 'Defina frame-ancestors restritivo ou X-Frame-Options DENY/SAMEORIGIN.')
    if single('x-content-type-options').lower() != 'nosniff':
        add('nosniff', 'low', 'Defina X-Content-Type-Options: nosniff.')
    policy = single('referrer-policy').lower().split(',')[-1].strip()
    if policy not in ('no-referrer', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin'):
        add('referrer_policy', 'low', 'Revise Referrer-Policy para limitar exposição de URLs.')
    if https:
        hsts = single('strict-transport-security')
        match = re.search(r'(?:^|;)\s*max-age\s*=\s*(\d+)\s*(?:;|$)', hsts, re.I)
        if not match or int(match[1]) < 15552000:
            add('hsts', 'medium', 'Em HTTPS, avalie HSTS com max-age >= 15552000 após validar todos os serviços.')
    return dict(https=https, findings=findings, evaluated_headers=len(headers))

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('headers', type=Path)
    parser.add_argument('--https', action='store_true', help='Evaluate HSTS for an HTTPS response')
    args = parser.parse_args()
    try:
        report = audit(args.headers.read_text(encoding='utf-8'), args.https)
    except (OSError, ValueError) as error:
        parser.exit(2, f'Error: {error}\n')
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 1 if report['findings'] else 0

if __name__ == '__main__':
    sys.exit(main())
