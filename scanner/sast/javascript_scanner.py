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
    from scanner.sast.tree_flow import TreeFlow
    from scanner.sast.flow import confidence,evidence,combine
    def inspect(node,args,flow):
        line=node.start_point.row+1+offset
        if node.type in ('call_expression','new_expression'):
            callee=text(node.child_by_field_name('function') or node.child_by_field_name('constructor'))
            if callee in ('eval','window.eval','Function','window.Function') and args and callee.split('.')[0] not in flow.env:
                value=combine(args)
                if not value.static:
                    add(ctx,path,line,'Dynamic JavaScript code execution','Code Security',evidence(value,callee),
                        'Use explicit functions and structured data instead of dynamically compiling code.','High' if value.sources else 'Medium',confidence(value))
            if callee=='document.write' and args:
                value=combine(args,preserve_html=True)
                if not value.static and not value.html_safe:
                    add(ctx,path,line,'Potential unsafe document.write','Injection',evidence(value,callee),
                        'Use textContent or safe DOM construction; sanitize HTML when HTML is required.','Medium',confidence(value))
        elif node.type=='assignment_expression':
            left=node.child_by_field_name('left');value=args[0]
            if left and left.type in ('member_expression','subscript_expression'):
                prop=text(left.child_by_field_name('property') or left.child_by_field_name('index')).strip('"\'')
                if prop in ('innerHTML','outerHTML') and not value.static and not value.html_safe:
                    add(ctx,path,line,'Potential unsafe DOM HTML assignment','Injection',evidence(value,prop),
                        'Use textContent for text, or a maintained HTML sanitizer before assigning HTML.','Medium',confidence(value))
    TreeFlow(ctx,inspect,'js').value(root)
    return True


def run(ctx):
    parsed=0;errors=[]
    for path,source in files(ctx,('.js','.jsx','.mjs','.cjs')):
        if analyze(ctx,path,source):
            parsed+=1
        else:
            errors.append(path)
    return {'parsed_files':parsed,'unparsed_files':errors[:100],'note':'Tree-sitter statement-order local variable and sanitizer context; comments and string contents do not trigger code rules. TypeScript and interprocedural data flow are not supported.'}
