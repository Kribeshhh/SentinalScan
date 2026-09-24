from tree_sitter import Language, Parser
import tree_sitter_javascript
import warnings
from scanner.sast.common import add,files


def walk(root):
    stack=[root]
    while stack:
        node=stack.pop();yield node
        stack.extend(reversed(node.named_children))


def text(node):
    return node.text.decode('utf-8',errors='replace') if node else ''


def parse_source(grammar, source):
    parser = Parser(Language(grammar.language()))
    with warnings.catch_warnings():
        warnings.simplefilter('ignore', DeprecationWarning)
        parser.timeout_micros = 2_000_000
    tree = parser.parse(source.encode())
    return tree.root_node if tree else None


def analyze(ctx,path,source,offset=0):
    root=parse_source(tree_sitter_javascript, source)
    if root is None or root.has_error:
        return False
    values={text(n.child_by_field_name('name')):n.child_by_field_name('value') for n in walk(root) if n.type=='variable_declarator'}
    def resolve(node):
        return values.get(text(node),node) if node and node.type=='identifier' else node
    def dynamic(node):
        node=resolve(node)
        if not node:
            return False
        if node.type in ('string','number','true','false','null'):
            return False
        if node.type=='template_string' and not any(n.type=='template_substitution' for n in walk(node)):
            return False
        if node.type=='call_expression' and text(node.child_by_field_name('function'))=='DOMPurify.sanitize':
            return False
        return True
    for node in walk(root):
        line=node.start_point.row+1+offset
        if node.type in ('call_expression','new_expression'):
            callee=text(node.child_by_field_name('function') or node.child_by_field_name('constructor'))
            args=node.child_by_field_name('arguments');args=args.named_children if args else []
            if callee in ('eval','window.eval','Function','window.Function') and args and dynamic(args[-1]):
                add(ctx,path,line,'Dynamic JavaScript code execution','Code Security','Parsed '+callee+' invocation uses dynamic source text.','Use explicit functions and structured data instead of dynamically compiling code.')
            if callee=='document.write' and args and any(dynamic(arg) for arg in args):
                add(ctx,path,line,'Potential unsafe document.write','Injection','Parsed document.write invocation receives a nonliteral value.','Use textContent or safe DOM construction; sanitize HTML when HTML is required.')
        elif node.type=='assignment_expression':
            left=node.child_by_field_name('left');right=node.child_by_field_name('right')
            if left and left.type in ('member_expression','subscript_expression'):
                prop=text(left.child_by_field_name('property') or left.child_by_field_name('index')).strip('"\'')
                if prop in ('innerHTML','outerHTML') and dynamic(right):
                    add(ctx,path,line,'Potential unsafe DOM HTML assignment','Injection','Parsed assignment to '+prop+' uses a nonliteral value without a directly recognized sanitizer.','Use textContent for text, or a maintained HTML sanitizer before assigning HTML.','Medium','Medium')
    return True


def run(ctx):
    parsed=0;errors=[]
    for path,source in files(ctx,('.js','.jsx','.mjs','.cjs')):
        if analyze(ctx,path,source):
            parsed+=1
        else:
            errors.append(path)
    return {'parsed_files':parsed,'unparsed_files':errors[:100],'note':'Tree-sitter syntax and one-step variable context; comments and string contents do not trigger code rules. TypeScript and interprocedural data flow are not supported.'}
