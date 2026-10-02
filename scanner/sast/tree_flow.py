"""Bounded syntax-tree local flow shared by the existing Java/JavaScript parsers."""
from dataclasses import replace
from scanner.sast.flow import Value,UNKNOWN,combine,merge_environments,sensitive_name
from scanner.sast.common import check_budget


def text(node):return node.text.decode('utf-8',errors='replace') if node else ''


class TreeFlow:
    def __init__(self,ctx,inspect,language):
        self.ctx=ctx;self.inspect=inspect;self.language=language;self.env={};self.types={};self.target=''

    def value(self,node):
        if node is None:return UNKNOWN
        kind=node.type
        if kind in ('string','string_literal','number','decimal_integer_literal','true','false','null','null_literal','character_literal'):
            return Value(static=True,literal=text(node).strip('"\''))
        if kind=='identifier':return self.env.get(text(node),Value(sensitive=sensitive_name(text(node))))
        if kind in ('class_declaration','class_definition'):
            env,types=self.env,self.types
            self.env=env.copy();self.types=types.copy()
            self.value(node.child_by_field_name('body'))
            self.env,self.types=env,types
            return UNKNOWN
        if kind in ('function_declaration','function_expression','arrow_function','method_definition','method_declaration','constructor_declaration','lambda_expression'):
            env,types,target=self.env,self.types,self.target
            self.env=env.copy();self.types=types.copy();self.target=''
            # A declaration in this function must not inherit an outer constant.
            def bind_locals(n):
                if n is None:return
                if n.type in ('function_declaration','function_expression','arrow_function','class_declaration','method_declaration'):return
                if n.type=='variable_declarator':
                    local=text(n.child_by_field_name('name'));self.env[local]=UNKNOWN
                for child in n.named_children:bind_locals(child)
            bind_locals(node.child_by_field_name('body'))
            params=node.child_by_field_name('parameters') or node.child_by_field_name('parameter')
            if params:
                def parameters(n):
                    if n.type in ('formal_parameter','spread_parameter'):
                        name=text(n.child_by_field_name('name'));self.types[name]=text(n.child_by_field_name('type'))
                        self.env[name]=Value(sensitive=sensitive_name(name));return
                    if n.type=='identifier':self.env[text(n)]=Value(sensitive=sensitive_name(text(n)));return
                    for child in n.named_children:parameters(child)
                parameters(params)
            self.value(node.child_by_field_name('body'))
            self.env,self.types,self.target=env,types,target
            name=text(node.child_by_field_name('name'))
            if name:self.env[name]=UNKNOWN
            return UNKNOWN
        if kind in ('if_statement','ternary_expression','conditional_expression'):
            condition=node.child_by_field_name('condition');self.value(condition)
            before=self.env.copy();types=self.types.copy()
            left=self.value(node.child_by_field_name('consequence'));branch=self.env.copy()
            self.env=before.copy();self.types=types.copy()
            right=self.value(node.child_by_field_name('alternative'))
            self.env=merge_environments(before,branch,self.env);self.types=types
            return combine([left,right],preserve_html=True)
        if kind in ('for_statement','for_in_statement','enhanced_for_statement','while_statement','do_statement','try_statement'):
            before=self.env.copy()
            for child in node.named_children:self.value(child)
            self.env=merge_environments(before,before,self.env)
            return UNKNOWN
        if kind=='variable_declarator':
            name=text(node.child_by_field_name('name'));previous=self.target;self.target=name
            value=self.value(node.child_by_field_name('value'));self.env[name]=value.assigned(name)
            if self.language=='java':self.types[name]=text(node.parent.child_by_field_name('type'))
            self.target=previous;return value
        if kind in ('assignment_expression','assignment'):
            left=node.child_by_field_name('left');right=node.child_by_field_name('right');value=self.value(right)
            operator=text(node.child_by_field_name('operator'))
            if operator not in ('','='):value=combine([self.value(left),value],constructed=True,preserve_html=True)
            self.inspect(node,[value],self)
            if left and left.type=='identifier':self.env[text(left)]=value.assigned(text(left))
            return value
        if kind in ('call_expression','new_expression','method_invocation','object_creation_expression'):
            function=node.child_by_field_name('function') or node.child_by_field_name('constructor')
            receiver=node.child_by_field_name('object')
            if function and function.type in ('member_expression','subscript_expression'):receiver=function.child_by_field_name('object')
            parent=self.value(receiver) if receiver else UNKNOWN
            args=node.child_by_field_name('arguments');args=[self.value(a) for a in args.named_children] if args else []
            self.inspect(node,args,self)
            name=text(function) if function else text(receiver)+'.'+text(node.child_by_field_name('name'))
            value=replace(combine([parent,*args]),static=False,html_safe=False,literal=None)
            if name=='DOMPurify.sanitize' and 'DOMPurify' not in self.env and args:
                return replace(args[0],html_safe=True)
            if self.language=='js' and (name in ('prompt','window.prompt') or name.startswith(('req.query.','req.body.','req.params.','req.cookies.','request.query.','request.body.'))):
                return replace(value,sources=(name,))
            if self.language=='java' and text(node.child_by_field_name('name')) in ('getParameter','getHeader','getQueryString','getReader','getInputStream') and (text(receiver) in ('request','req') or 'ServletRequest' in self.types.get(text(receiver),'')):
                return replace(value,sources=('HTTP request input',))
            if text(node.child_by_field_name('type')).split('.')[-1]=='ObjectInputStream':return replace(value,constructed=False)
            if name.endswith(('.format','.formatted','.concat','.join')):
                operands=args if name in ('String.format','java.lang.String.format') else [parent,*args]
                return combine(operands,constructed=True,preserve_html=self.language=='js')
            return value
        if kind in ('member_expression','subscript_expression','field_access','array_access'):
            name=text(node)
            if self.language=='js' and (name in ('location.hash','location.search','window.location.hash','window.location.search','document.URL','document.documentURI') or name.startswith(('req.query','req.body','req.params','req.cookies','request.query','request.body'))):
                return Value(sources=('Browser/HTTP input',))
            return self.value(node.child_by_field_name('object') or node.child_by_field_name('array'))
        if kind=='template_string' and not any(n.type=='template_substitution' for n in node.named_children):return Value(static=True)
        if kind in ('binary_expression','template_string'):
            return combine([self.value(n) for n in node.named_children],constructed=True,preserve_html=True)
        if kind in ('string_fragment','escape_sequence'):return Value(static=True)
        values=[]
        for child in node.named_children:
            if 'deadline' in self.ctx:check_budget(self.ctx)
            values.append(self.value(child))
        return combine(values,preserve_html=True)
