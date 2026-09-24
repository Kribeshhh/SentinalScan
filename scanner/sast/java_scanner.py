import tree_sitter_java
from scanner.sast.javascript_scanner import walk,text,parse_source
from scanner.sast.common import add,files


def run(ctx):
    parsed=0;errors=[]
    for path,source in files(ctx,('.java',)):
        root=parse_source(tree_sitter_java, source)
        if root is None or root.has_error:
            errors.append(path);continue
        parsed+=1;values={};types={}
        for node in walk(root):
            if node.type=='variable_declarator':
                identifier=text(node.child_by_field_name('name'));values[identifier]=node.child_by_field_name('value')
                types[identifier]=text(node.parent.child_by_field_name('type'))
            if node.type=='formal_parameter':
                types[text(node.child_by_field_name('name'))]=text(node.child_by_field_name('type'))
        def resolve(node):
            return values.get(text(node)) or node if node and node.type=='identifier' else node
        def dynamic(node):
            node=resolve(node)
            return bool(node and node.type not in ('string_literal','decimal_integer_literal','true','false','null_literal'))
        def constructed(node):
            node=resolve(node)
            return bool(node and (node.type=='binary_expression' or (node.type=='method_invocation' and text(node.child_by_field_name('name')) in ('format','formatted','toString'))))
        for node in walk(root):
            if node.type not in ('method_invocation','object_creation_expression'):
                continue
            method=text(node.child_by_field_name('name'));receiver=node.child_by_field_name('object')
            obj=text(receiver);kind=text(node.child_by_field_name('type'))
            args=node.child_by_field_name('arguments');args=args.named_children if args else []
            line=node.start_point.row+1
            if (method=='exec' and (obj.startswith('Runtime.getRuntime()') or types.get(obj)=='Runtime') or kind=='ProcessBuilder') and args and any(dynamic(arg) for arg in args):
                add(ctx,path,line,'Dynamic Java process execution','Code Security','Parsed Runtime.exec or ProcessBuilder uses a nonliteral argument.','Use a fixed executable and validated argument list; avoid invoking a shell with untrusted input.')
            if method in ('execute','executeQuery','executeUpdate','prepareStatement') and args and constructed(args[0]):
                add(ctx,path,line,'Potential SQL injection in Java query','Injection','A SQL-like API receives concatenated or formatted query text.','Use PreparedStatement placeholders and bound parameters.','High')
            if method=='readObject' and ('ObjectInputStream' in types.get(obj,'') or 'ObjectInputStream' in obj):
                add(ctx,path,line,'Potential unsafe Java deserialization','Deserialization','ObjectInputStream.readObject is used; input trust and filtering require review.','Avoid deserializing untrusted object graphs; use data-only formats and explicit allowlists.')
            if method=='getInstance' and obj.split('.')[-1] in ('MessageDigest','Cipher') and args:
                algorithm=text(resolve(args[0])).strip('"').upper()
                if algorithm in ('MD5','SHA1','SHA-1','DES','RC4') or '/ECB/' in algorithm:
                    add(ctx,path,line,'Weak Java cryptographic algorithm','Cryptography','A cryptographic factory selects a weak hash/cipher or ECB mode.','Use modern hashes or authenticated encryption, and purpose-built password hashing where appropriate.','Low','High')
    return {'parsed_files':parsed,'unparsed_files':errors[:100],'note':'Syntax-aware heuristics with basic declared-type/assignment context; no Java build, dependency resolution or bytecode execution.'}
