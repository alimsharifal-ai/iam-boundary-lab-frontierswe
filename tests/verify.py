"""Deterministic behavior-only IAM security verifier."""
import os
import traceback
from iamlab.engine import PolicyError, authorize, authorize_assume_role


def policy(*statements):
    return {"Statement": list(statements)}


def stmt(effect="Allow", action="*", resource="*", **other):
    return {"Effect": effect, "Action": action, "Resource": resource, **other}


def req(action="s3:GetObject", resource="arn:lab:s3:::prod/file", principal="tenant-a/alice", **context):
    return {"action": action, "resource": resource, "principal": principal, "context": context}


def same(actual, expected):
    assert actual == expected, f"expected {expected}, got {actual}"


def basics():
    p = policy(stmt(action=["s3:GetObject", "s3:ListBucket"], resource="arn:lab:s3:::prod/*"))
    same(authorize(req(), p), "Allow")
    same(authorize(req("s3:DeleteObject"), p), "Deny")
    same(authorize(req(resource="arn:lab:s3:::other/file"), p), "Deny")
    same(authorize(req("S3:GETOBJECT"), p), "Allow")


def deny_precedence():
    p = policy(stmt(), stmt("Deny", "iam:CreateAccessKey", "*"))
    same(authorize(req("iam:CreateAccessKey"), p), "Deny")
    same(authorize(req("iam:ListUsers"), p), "Allow")
    restrictive = policy(stmt("Deny", "s3:GetObject", "arn:lab:s3:::prod/*"))
    same(authorize(req(), policy(stmt()), resource=restrictive), "Deny")


def boundaries():
    broad = policy(stmt())
    read_only = policy(stmt(action="s3:Get*"))
    same(authorize(req(), broad, boundary=read_only), "Allow")
    same(authorize(req("s3:DeleteObject"), broad, boundary=read_only), "Deny")
    same(authorize(req(), broad, organization=policy(stmt(action="ec2:*"))), "Deny")
    same(authorize(req(), broad, resource=policy(stmt(action="s3:PutObject"))), "Deny")
    same(authorize(req(), broad, boundary=read_only, organization=broad, resource=broad), "Allow")


def inverse_selectors():
    p = policy(stmt(), {"Effect": "Deny", "NotAction": ["s3:Get*", "s3:List*"], "Resource": "*"})
    same(authorize(req("iam:CreateUser"), p), "Deny")
    same(authorize(req(), p), "Allow")
    q = policy(stmt(), {"Effect": "Deny", "Action": "*", "NotResource": "arn:lab:s3:::public/*"})
    same(authorize(req(resource="arn:lab:s3:::public/ok"), q), "Allow")
    same(authorize(req(resource="arn:lab:s3:::private/secret"), q), "Deny")


def strings_and_tags():
    p = policy(stmt(Condition={"StringEquals": {"aws:PrincipalTag/team": ["payments", "audit"]}}))
    same(authorize(req(**{"aws:PrincipalTag/team": "payments"}), p), "Allow")
    same(authorize(req(**{"aws:PrincipalTag/team": "PaymentS"}), p), "Deny")
    p = policy(stmt(Condition={"StringLike": {"object:key": "reports/2026/*"},
                                     "StringNotLike": {"object:key": "*/private/*"}}))
    same(authorize(req(**{"object:key": "reports/2026/public/jan"}), p), "Allow")
    same(authorize(req(**{"object:key": "reports/2026/private/jan"}), p), "Deny")
    q = policy(stmt(Condition={"StringNotEquals": {"env": ["prod", "stage"]}}))
    same(authorize(req(env="dev"), q), "Allow")
    same(authorize(req(env="prod"), q), "Deny")
    same(authorize(req(), q), "Deny")


def mfa_and_null():
    mfa = policy(stmt(Condition={"Bool": {"aws:MultiFactorAuthPresent": "true"}}))
    same(authorize(req(**{"aws:MultiFactorAuthPresent": True}), mfa), "Allow")
    same(authorize(req(**{"aws:MultiFactorAuthPresent": "FALSE"}), mfa), "Deny")
    same(authorize(req(), mfa), "Deny")
    missing = policy(stmt(Condition={"Null": {"session:breakglass": "true"}}))
    same(authorize(req(), missing), "Allow")
    same(authorize(req(**{"session:breakglass": None}), missing), "Allow")
    same(authorize(req(**{"session:breakglass": "issued"}), missing), "Deny")


def ip_network():
    p = policy(stmt(Condition={"IpAddress": {"aws:SourceIp": ["10.2.0.0/16", "2001:db8::/32"]}}))
    same(authorize(req(**{"aws:SourceIp": "10.2.3.4"}), p), "Allow")
    same(authorize(req(**{"aws:SourceIp": "2001:db8::9"}), p), "Allow")
    same(authorize(req(**{"aws:SourceIp": "10.3.1.1"}), p), "Deny")
    same(authorize(req(**{"aws:SourceIp": "not-an-ip"}), p), "Deny")


def trust():
    assume = req("sts:AssumeRole", "arn:lab:iam::tenant-b:role/ops", "tenant-a/alice")
    identity = policy(stmt(action="sts:AssumeRole", resource="arn:lab:iam::tenant-b:role/ops"))
    trust_policy = policy(stmt(action="sts:AssumeRole", Principal="tenant-a/alice"))
    same(authorize_assume_role(assume, identity, trust_policy), "Allow")
    same(authorize_assume_role({**assume, "principal": "tenant-c/eve"}, identity, trust_policy), "Deny")
    same(authorize_assume_role(assume, identity, policy(stmt(Principal="tenant-c/*"))), "Deny")
    same(authorize_assume_role(req("iam:PassRole"), policy(stmt()), policy(stmt(Principal="*"))), "Deny")


def trust_escalation():
    assume = req("sts:AssumeRole", "arn:lab:iam::prod:role/admin", "external/contractor")
    trust_policy = policy(stmt(Principal="*"), {"Effect": "Deny", "Action": "sts:AssumeRole",
                                                "Resource": "*", "Principal": "external/*"})
    same(authorize_assume_role(assume, policy(stmt()), trust_policy), "Deny")
    q = policy(stmt(Principal="tenant-a/*"), {"Effect": "Deny", "Action": "sts:AssumeRole",
                                               "Resource": "*", "NotPrincipal": "tenant-a/admin"})
    same(authorize_assume_role({**assume, "principal": "tenant-a/intern"}, policy(stmt()), q), "Deny")
    same(authorize_assume_role({**assume, "principal": "tenant-a/admin"}, policy(stmt()), q), "Allow")
    same(authorize_assume_role(assume, policy(stmt()), policy(stmt(Principal="*")),
                               boundary=policy(stmt(action="s3:*"))), "Deny")


def fail_closed():
    for broken in [None, {}, {"Statement": {"Effect": "Allow", "Action": "*"}},
                   {"Statement": stmt(action="*", NotResource="*")},
                   {"Statement": {"Effect": "Maybe", "Action": "*", "Resource": "*"}},
                   {"Statement": {"Effect": "Allow", "Action": "*", "NotAction": "*", "Resource": "*"}}]:
        try:
            authorize(req(), broken)
            assert False, f"malformed policy was accepted: {broken}"
        except PolicyError:
            pass
    for bad in [{}, {"action": None, "resource": "*", "principal": "x"}]:
        try:
            authorize(bad, policy(stmt()))
            assert False
        except PolicyError:
            pass


CASES = [basics, deny_precedence, boundaries, inverse_selectors, strings_and_tags,
         mfa_and_null, ip_network, trust, trust_escalation, fail_closed]
passed = 0
for fn in CASES:
    try:
        fn()
        print("PASS", fn.__name__)
        passed += 1
    except Exception as exc:
        print("FAIL", fn.__name__, type(exc).__name__, str(exc))
        traceback.print_exc(limit=2)
score = float(passed == len(CASES))
destination = os.environ.get("IAM_REWARD_DIR", "/logs/verifier")
os.makedirs(destination, exist_ok=True)
with open(os.path.join(destination, "reward.txt"), "w", encoding="utf8") as out:
    out.write(f"{score:.3f}\n")
print(f"SCORE {score:.3f} ({passed}/{len(CASES)} groups)")
