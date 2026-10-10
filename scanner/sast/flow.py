"""Small immutable abstract values. No source values enter finding evidence."""
from dataclasses import dataclass, replace
import re


@dataclass(frozen=True)
class Value:
    static: bool = False
    literal: object = None
    sources: tuple = ()
    trace: tuple = ()
    constructed: bool = False
    html_safe: bool = False
    sensitive: bool = False
    callable_name: str | None = None
    identity: str | None = None
    uncertain: bool = False
    calls: tuple = ()
    protections: tuple = ()

    def assigned(self, name):
        return replace(self, trace=(self.trace+(name,))[-8:],
                       sensitive=self.sensitive or sensitive_name(name))


UNKNOWN = Value()


def sensitive_name(name):
    return bool(re.search(r'password|passwd|credential|signature|auth|secret',name,re.I))


def combine(values, constructed=False, preserve_html=False):
    values=list(values)
    if not values:return UNKNOWN
    dynamic=[v for v in values if not v.static]
    protections=set(dynamic[0].protections) if dynamic else set()
    for value in dynamic[1:]:protections.intersection_update(value.protections)
    return Value(static=all(v.static for v in values),
        sources=tuple(dict.fromkeys(s for v in values for s in v.sources))[:4],
        trace=tuple(dict.fromkeys(s for v in values for s in v.trace))[-8:],
        constructed=constructed or any(v.constructed for v in values),
        html_safe=preserve_html and all(v.static or v.html_safe for v in values),
        sensitive=any(v.sensitive for v in values),
        uncertain=any(v.uncertain for v in values),
        calls=tuple(dict.fromkeys(s for v in values for s in v.calls))[-6:],protections=tuple(sorted(protections)))


def join(left,right):
    if left==right:return left
    return combine([left,right],preserve_html=True)


def merge_environments(before,*branches):
    keys=set(before).union(*(set(b) for b in branches))
    return {key: _join_many([b.get(key,UNKNOWN) for b in branches]) for key in keys}


def _join_many(values):
    result=values[0]
    for value in values[1:]:result=join(result,value)
    return result


def confidence(value):
    return 'High' if value.sources and not value.uncertain else 'Medium' if value.sources else 'Low' if value.static else 'Medium'


def evidence(value, sink):
    origin='Recognized input '+', '.join(value.sources) if value.sources else 'Dynamic value; original input source unknown'
    route=(' → '+' → '.join(value.trace)) if value.trace else ''
    return origin+route+' → '+sink+'. No protection recognized for this operation; static analysis does not prove exploitability.'
