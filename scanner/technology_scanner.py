import re
from bs4 import BeautifulSoup
from scanner.common import baseline


def run(ctx):
    response = baseline(ctx)
    server = response.header('Server').lower()
    powered = response.header('X-Powered-By').lower()
    cookie_names = ' '.join(v.split('=',1)[0].lower() for k,v in response.headers if k.lower() == 'set-cookie')
    soup = BeautifulSoup(response.text, 'html.parser') if response.html else None
    refs = ' '.join(str(tag.get('src') or tag.get('href') or '') for tag in soup.find_all(['script','link'])[:200]).lower() if soup else ''
    generator = ' '.join(str(t.get('content','')) for t in soup.find_all('meta', attrs={'name':re.compile('generator',re.I)})) if soup else ''
    indicators = [('Apache','apache' in server,'Server header'),('Nginx','nginx' in server,'Server header'),('IIS','iis' in server,'Server header'),('PHP','php' in powered or 'phpsessid' in cookie_names,'Header or cookie name'),('WordPress','wp-content/' in refs or 'wordpress' in generator.lower(),'Asset reference or generator'),('Django','csrftoken' in cookie_names,'Cookie naming heuristic; unconfirmed'),('Flask','werkzeug' in server,'Werkzeug server indicator; Flask is unconfirmed'),('jQuery','jquery' in refs,'Script reference'),('Bootstrap','bootstrap' in refs,'Asset reference')]
    return {'technologies':[{'name':name,'indicator':why} for name,matched,why in indicators if matched], 'note':'Passive indicators are observations, not vulnerabilities; heuristic framework matches may be wrong.'}
