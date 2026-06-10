# Core exact-computation logic (the brain of the math service).
import sympy as sp
from sympy.parsing.sympy_parser import (
    parse_expr, standard_transformations, implicit_multiplication_application,
    convert_xor,
)

TRANSFORMS = standard_transformations + (implicit_multiplication_application, convert_xor)
# Block obviously dangerous tokens before parsing (defense in depth).
BANNED = ('__', 'import', 'lambda', 'eval', 'exec', 'open', 'os.', 'sys.')

def _parse(s):
    low = str(s).lower()
    if any(b in low for b in BANNED):
        raise ValueError('disallowed token in expression')
    return parse_expr(str(s), transformations=TRANSFORMS, evaluate=True)

def _eq(s):
    # accept "lhs = rhs" or a bare expression (treated as expr = 0)
    if '=' in s and '==' not in s:
        l, r = s.split('=', 1)
        return sp.Eq(_parse(l), _parse(r))
    return sp.Eq(_parse(s), 0)

def compute(action, expr=None, **kw):
    a = action.lower()
    if a == 'evaluate':
        e = _parse(expr); val = sp.nsimplify(e) if e.free_symbols == set() else sp.simplify(e)
        return {'exact': str(val), 'decimal': str(sp.N(e, 12)) if e.free_symbols == set() else None}
    if a == 'solve':
        var = sp.Symbol(kw.get('variable', 'x'))
        sol = sp.solve(_eq(expr), var, dict=False)
        return {'solutions': [str(s) for s in sol]}
    if a == 'solve_system':
        eqs = [_eq(e) for e in kw['equations']]
        vrs = [sp.Symbol(v) for v in kw.get('variables', ['x', 'y'])]
        sol = sp.solve(eqs, vrs, dict=True)
        return {'solutions': [{str(k): str(v) for k, v in d.items()} for d in sol]}
    if a == 'diff':
        var = sp.Symbol(kw.get('variable', 'x'))
        return {'result': str(sp.diff(_parse(expr), var))}
    if a == 'integrate':
        var = sp.Symbol(kw.get('variable', 'x'))
        lo, hi = kw.get('lower'), kw.get('upper')
        if lo is not None and hi is not None:
            r = sp.integrate(_parse(expr), (var, _parse(lo), _parse(hi)))
            return {'result': str(r), 'decimal': str(sp.N(r, 12))}
        return {'result': str(sp.integrate(_parse(expr), var)) + ' + C'}
    if a == 'simplify': return {'result': str(sp.simplify(_parse(expr)))}
    if a == 'factor':   return {'result': str(sp.factor(_parse(expr)))}
    if a == 'expand':   return {'result': str(sp.expand(_parse(expr)))}
    if a == 'limit':
        var = sp.Symbol(kw.get('variable', 'x'))
        return {'result': str(sp.limit(_parse(expr), var, _parse(kw.get('to', '0'))))}
    if a == 'verify':
        # does 'value' satisfy equation 'expr'? returns true/false EXACTLY
        var = sp.Symbol(kw.get('variable', 'x'))
        eq = _eq(expr); val = _parse(kw['value'])
        diff = sp.simplify(eq.lhs.subs(var, val) - eq.rhs.subs(var, val))
        return {'satisfies': bool(diff == 0), 'residual': str(diff)}
    raise ValueError(f'unknown action: {action}')

# ---- self-test ----
if __name__ == '__main__':
    tests = [
        ('evaluate', {'expr': '2/3 + 1/6'}),
        ('evaluate', {'expr': '68473*9156'}),
        ('solve',    {'expr': '3x^2 - 7x - 6 = 0'}),
        ('solve_system', {'equations': ['2x+3y=13','x-y=-1'], 'variables':['x','y']}),
        ('diff',     {'expr': 'x^3 sin(x)'}),
        ('integrate',{'expr': 'x^2 sin(x)', 'lower':'0', 'upper':'pi'}),
        ('integrate',{'expr': '2x + 1'}),
        ('simplify', {'expr': '(x^2-1)/(x-1)'}),
        ('factor',   {'expr': 'x^2 - 5x + 6'}),
        ('verify',   {'expr': '3x^2-7x-6=0', 'value':'3'}),
        ('verify',   {'expr': '3x^2-7x-6=0', 'value':'2'}),
    ]
    for act, kw in tests:
        try: print(f'{act:13}', compute(act, **kw))
        except Exception as e: print(f'{act:13} ERROR {e}')
