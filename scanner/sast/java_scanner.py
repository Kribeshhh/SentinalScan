"""Java syntax and local variable flow; no compilation or execution."""
import tree_sitter_java
from scanner.sast.javascript_scanner import text,parse_source
from scanner.sast.common import add,files
from scanner.sast.evidence import semantic
from scanner.sast.tree_flow import TreeFlow
from scanner.sast.flow import UNKNOWN,combine,confidence,evidence,sensitive_name


def run(ctx):
    parsed=0;errors=[]
    for path,source in files(ctx,('.java',)):
        root=parse_source(tree_sitter_java,source)
        if root is None or root.has_error:errors.append(path);continue
        parsed+=1
        def inspect(node,args,flow):
            if node.type not in ('method_invocation','object_creation_expression'):return
            method=text(node.child_by_field_name('name'));receiver=node.child_by_field_name('object')
            obj=text(receiver);kind=text(node.child_by_field_name('type')).split('.')[-1]
            line=node.start_point.row+1;first=args[0] if args else UNKNOWN
            def report(title,category,value,recommendation,severity='Medium',level=None):
                detail=evidence(value,method or kind)
                if category=='Cryptography':
                    detail='Weak algorithm selected; '+('security-sensitive naming/context detected.' if severity=='High' else 'purpose and deployment require review; checksum-only hashing may be acceptable.')
                add(ctx,path,line,title,category,detail,recommendation,severity,level or confidence(value),semantic=semantic(node,value,method or kind,'Java'))
            runtime=method=='exec' and (obj.startswith(('Runtime.getRuntime()','java.lang.Runtime.getRuntime()')) or flow.types.get(obj,'').split('.')[-1]=='Runtime')
            if (runtime or kind=='ProcessBuilder') and args:
                value=combine(args)
                if not value.static:report('Dynamic Java process execution','Code Security',value,'Use a fixed executable and validated argument list; avoid invoking a shell with untrusted input.','High' if value.sources else 'Medium')
            if method in ('execute','executeQuery','executeUpdate','prepareStatement') and args and not first.static and (first.constructed or first.sources):
                report('Potential SQL injection in Java query','Injection',first,'Use PreparedStatement placeholders and bound parameters.','High')
            if method=='readObject' and ('ObjectInputStream' in flow.types.get(obj,'') or 'ObjectInputStream' in obj):
                value=flow.env.get(obj,UNKNOWN)
                report('Potential unsafe Java deserialization','Deserialization',value,'Avoid deserializing untrusted object graphs; use data-only formats and explicit allowlists.','High' if value.sources else 'Medium','High' if value.sources else 'Low')
            if method=='getInstance' and obj.split('.')[-1] in ('MessageDigest','Cipher') and args:
                algorithm=str(first.literal or '').upper()
                weak_hash=algorithm in ('MD5','SHA1','SHA-1')
                weak_cipher=algorithm in ('DES','RC4') or '/ECB/' in algorithm
                if weak_hash or weak_cipher:
                    sensitive=sensitive_name(flow.target)
                    report('Weak Java cryptographic algorithm','Cryptography',first,
                        'Use dedicated password hashing for passwords or authenticated encryption for sensitive data. Checksum-only hash use needs contextual review.',
                        'High' if sensitive else 'Medium' if weak_cipher else 'Low', 'Medium' if sensitive or weak_cipher else 'Low')
        TreeFlow(ctx,inspect,'java').value(root)
    return {'parsed_files':parsed,'unparsed_files':errors[:100],'note':'Tree-sitter local statement-order flow and declared types; no interprocedural flow, Java build or code execution. Deserialization filters require manual review.'}
