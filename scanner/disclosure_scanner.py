import re
from scanner.common import baseline, issue
from scanner.sqli_scanner import matches


def run(ctx):
    response = baseline(ctx)
    signatures = {'Python traceback':r'Traceback \(most recent call last\)', 'Java stack trace':r'(?m)^\s*at [\w.$]+\([\w.]+\.java:\d+\)', 'PHP verbose error':r'(?:Fatal error|Warning):.*(?:on line \d+)', 'ASP.NET exception':r'(?:Stack Trace:|Server Error in .*/.*Application)'}
    detected = [name for name,pattern in signatures.items() if re.search(pattern,response.text)]
    detected += sorted(matches(response.text))
    if detected:
        issue(ctx,'Verbose application error disclosure','Low','Information Disclosure','Observed error signatures: ' + ', '.join(detected) + '. Raw errors are not stored.','Disable debug output and return generic client-facing errors while logging details securely.','High')
    versions = []
    for header in ('Server','X-Powered-By'):
        value = response.header(header)
        match = re.search(r'\b([A-Za-z][\w.-]{1,25})[ /](\d+\.\d+(?:\.\d+)?)', value)
        if match:
            versions.append(match.group(1) + '/' + match.group(2))
    if versions:
        issue(ctx,'Server or framework version disclosed','Informational','Information Disclosure','Version indicators: ' + ', '.join(versions), 'Minimize unnecessary version banners and keep components patched. A version banner alone does not establish vulnerability.','High')
    maps = len(re.findall(r'sourceMappingURL\s*=',response.text))
    if maps:
        issue(ctx,'Source map reference disclosed','Informational','Information Disclosure',f'The baseline response contains {maps} source map references. Referenced files were not downloaded.','Review whether publishing source maps is intended; avoid exposing sensitive source details.','Low')
    return {'error_signatures':detected,'version_indicators':versions,'source_map_references':maps}
