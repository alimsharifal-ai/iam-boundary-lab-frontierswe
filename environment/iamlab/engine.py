"""IAM policy decision point for a synthetic cloud provider."""

class PolicyError(Exception):
    pass


def authorize(request, identity, boundary=None, organization=None, resource=None):
    raise NotImplementedError


def authorize_assume_role(request, identity, trust, boundary=None, organization=None):
    raise NotImplementedError
