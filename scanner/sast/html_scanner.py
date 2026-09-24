import re
from bs4 import BeautifulSoup,Comment
from scanner.sast.common import add,files
from scanner.sast.javascript_scanner import analyze


def run(ctx):
    count=0;script_errors=0
    for path,source in files(ctx,('.html','.htm')):
        count+=1;soup=BeautifulSoup(source,'html.parser')
        for form in soup.find_all('form'):
            password=form.find('input',attrs={'type':re.compile('password',re.I)})
            if password and form.get('method','get').lower()=='get':
                add(ctx,path,form.sourceline or 1,'Password form uses GET','Authentication','An HTML password input belongs to a form submitted with GET.','Use POST over HTTPS and prevent sensitive values from entering URLs.','Medium','High')
            if str(form.get('action','')).lower().startswith('http://'):
                add(ctx,path,form.sourceline or 1,'Form submits over unencrypted HTTP','Configuration','A form action explicitly uses HTTP.','Submit forms over HTTPS.','Medium','High')
        for element in soup.find_all(['script','iframe','link']):
            ref=str(element.get('src') or element.get('href') or '')
            if ref.startswith('http://'):
                add(ctx,path,element.sourceline or 1,'Insecure external resource transport','Information Disclosure','A script, iframe or linked resource uses an explicit HTTP URL.','Serve and load resources over HTTPS; review the trust of external resources.','Low','High')
            if element.name=='script' and not element.get('src'):
                source_type=str(element.get('type','')).lower()
                if source_type in ('','text/javascript','application/javascript','module') and not analyze(ctx,path,element.get_text(),(element.sourceline or 1)-1):
                    script_errors+=1
        for comment in soup.find_all(string=lambda value:isinstance(value,Comment)):
            if re.search(r'(?:disable|bypass|skip)\s+(?:auth|authentication|authorization)|(?:password|secret|token)\s*[:=]',str(comment),re.I):
                add(ctx,path,1,'Potential sensitive HTML comment','Information Disclosure','An HTML comment mentions credentials or an authentication bypass. Comment contents are omitted.','Remove sensitive deployment notes and credentials from client-delivered markup.','Low','Low')
    return {'parsed_files':count,'unparsed_inline_scripts':script_errors,'note':'HTML and inline JavaScript are parsed without rendering, executing scripts or fetching resources.'}
