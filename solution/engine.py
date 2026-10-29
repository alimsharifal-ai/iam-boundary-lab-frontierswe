"""Reference policy engine. Offline authorization only; no cloud SDK calls."""
from fnmatch import fnmatchcase
import ipaddress


class PolicyError(Exception):
    pass


def _strings(value, label):
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and value and all(isinstance(x, str) for x in value):
        return value
    raise PolicyError(f"invalid {label}")


def _request(req):
    if not isinstance(req, dict):
        raise PolicyError("request must be mapping")
    for field in ("action", "resource", "principal"):
        if not isinstance(req.get(field), str) or not req[field]:
            raise PolicyError(f"invalid request {field}")
    if not isinstance(req.get("context", {}), dict):
        raise PolicyError("invalid request context")
    return req


def _select(statement, positive, negative, candidate, ignore_case=False):
    has_positive = positive in statement
    has_negative = negative in statement
    if has_positive == has_negative:
        raise PolicyError(f"exactly one of {positive}/{negative} required")
    patterns = _strings(statement[positive if has_positive else negative], positive)
    if ignore_case:
        candidate = candidate.lower()
        patterns = [p.lower() for p in patterns]
    matched = any(fnmatchcase(candidate, p) for p in patterns)
    return matched if has_positive else not matched


def _bool(v):
    if isinstance(v, bool):
        return v
    if isinstance(v, str) and v.lower() in ("true", "false"):
        return v.lower() == "true"
    raise ValueError("invalid boolean")


def _condition_match(conditions, ctx):
    if not isinstance(conditions, dict):
        raise PolicyError("Condition must be mapping")
    supported = {"StringEquals", "StringNotEquals", "StringLike", "StringNotLike", "Bool", "Null", "IpAddress"}
    for operator, clauses in conditions.items():
        if operator not in supported or not isinstance(clauses, dict) or not clauses:
            raise PolicyError("invalid condition operator or clauses")
        for key, values in clauses.items():
            if not isinstance(key, str) or not key:
                raise PolicyError("invalid context key")
            expected = _strings(values, "condition value") if not isinstance(values, bool) else [values]
            actual = ctx.get(key)
            if operator == "Null":
                try:
                    match = any((actual is None) == _bool(v) for v in expected)
                except ValueError as exc:
                    raise PolicyError("invalid Null condition") from exc
            elif actual is None:
                match = False
            elif operator == "Bool":
                try:
                    match = any(_bool(actual) == _bool(v) for v in expected)
                except ValueError:
                    match = False
            elif operator == "IpAddress":
                try:
                    addr = ipaddress.ip_address(actual)
                    match = any(addr in ipaddress.ip_network(v, strict=False) for v in expected)
                except (ValueError, TypeError):
                    match = False
            elif not isinstance(actual, str):
                match = False
            elif operator in ("StringEquals", "StringNotEquals"):
                found = any(actual == v for v in expected)
                match = found if operator == "StringEquals" else not found
            else:
                found = any(fnmatchcase(actual, v) for v in expected)
                match = found if operator == "StringLike" else not found
            if not match:
                return False
    return True


def _statements(policy):
    if not isinstance(policy, dict) or "Statement" not in policy:
        raise PolicyError("invalid policy")
    statements = policy["Statement"]
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        raise PolicyError("invalid statements")
    return statements


def _evaluate(policy, req, trust=False):
    allow, deny = False, False
    for stmt in _statements(policy):
        if not isinstance(stmt, dict) or stmt.get("Effect") not in ("Allow", "Deny"):
            raise PolicyError("invalid statement")
        action = _select(stmt, "Action", "NotAction", req["action"], ignore_case=True)
        resource = _select(stmt, "Resource", "NotResource", req["resource"])
        principal = True
        if trust:
            principal = _select(stmt, "Principal", "NotPrincipal", req["principal"])
        cond = _condition_match(stmt.get("Condition", {}), req.get("context", {}))
        if action and resource and principal and cond:
            if stmt["Effect"] == "Deny":
                deny = True
            else:
                allow = True
    return allow, deny


def authorize(request, identity, boundary=None, organization=None, resource=None):
    req = _request(request)
    if identity is None:
        raise PolicyError("identity policy is required")
    policies = [identity, boundary, organization, resource]
    decisions = [_evaluate(p, req) for p in policies if p is not None]
    if any(deny for _, deny in decisions):
        return "Deny"
    return "Allow" if decisions and all(allow for allow, _ in decisions) else "Deny"


def authorize_assume_role(request, identity, trust, boundary=None, organization=None):
    req = _request(request)
    if identity is None or trust is None:
        raise PolicyError("identity and trust policies are required")
    if req["action"].lower() != "sts:assumerole":
        return "Deny"
    policies = [(identity, False), (boundary, False), (organization, False), (trust, True)]
    decisions = [_evaluate(p, req, is_trust) for p, is_trust in policies if p is not None]
    if trust is None or any(deny for _, deny in decisions):
        return "Deny"
    return "Allow" if decisions and all(allow for allow, _ in decisions) else "Deny"
