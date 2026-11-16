"""Shared Docker resource identity and command scoping for StarryNet runs.

The owner label is the authority for cleanup. The traditional service name is
kept as the default for old callers, but resources without the owner label are
never considered owned by this run.
"""
import os
import re
import shlex


OWNER_ENV = 'STARRYNET_OWNER'
SERVICE_ENV = 'STARRYNET_SERVICE'
OWNER_LABEL = 'starrynet.owner'
DEFAULT_SERVICE = 'constellation-test'
DEFAULT_OWNER = 'constellation-test'

_SAFE_RESOURCE_VALUE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$')
_STARRYNET_NETWORK_NAME = re.compile(
    r'^(?:GS_[0-9]+|GSL_[0-9]+-[0-9]+|'
    r'La_[0-9]+-[0-9]+_[0-9]+-[0-9]+|'
    r'Le_[0-9]+-[0-9]+_[0-9]+-[0-9]+)$')
_NETWORK_CREATE_VALUE_OPTIONS = {
    '--aux-address', '--config-from', '--driver', '--gateway', '--ip-range',
    '--ipam-driver', '--ipam-opt', '--label', '--opt', '--scope', '--subnet',
}
_NETWORK_CREATE_FLAGS = {
    '--attachable', '--config-only', '--internal', '--ipv6', '--ingress',
}


def environment_for(remote=None):
    """Return the relevant process environment, including executor overrides."""
    environment = os.environ.copy()
    overrides = getattr(remote, 'env_overrides', None)
    if isinstance(overrides, dict):
        environment.update(overrides)
    return environment


def configure_executor(remote, owner, service):
    """Persist one resolved identity for subsequent local/SSH subprocesses."""
    if remote is None:
        return
    overrides = getattr(remote, 'env_overrides', None)
    if not isinstance(overrides, dict):
        overrides = {}
        try:
            remote.env_overrides = overrides
        except (AttributeError, TypeError):
            return
    overrides[OWNER_ENV] = owner
    overrides[SERVICE_ENV] = service


def resource_identity(environment=None, service=None, owner=None):
    """Resolve and validate one service/owner pair.

    Explicit executor environment wins over legacy positional arguments. The
    positional service argument preserves compatibility with pre-scope APIs.
    """
    if environment is None:
        environment = os.environ
    resolved_service = (environment[SERVICE_ENV] if SERVICE_ENV in environment
                        else service or DEFAULT_SERVICE)
    resolved_owner = (environment[OWNER_ENV] if OWNER_ENV in environment
                      else owner or DEFAULT_OWNER)
    for name, value in ((SERVICE_ENV, resolved_service),
                        (OWNER_ENV, resolved_owner)):
        if not isinstance(value, str) or not _SAFE_RESOURCE_VALUE.match(value):
            raise ValueError('{} must be a safe non-empty resource identifier'.format(name))
    return resolved_owner, resolved_service


def scoped_shell(command, environment=None):
    """Export the run identity in a remote shell without changing its profile."""
    owner, service = resource_identity(environment)
    return 'export {0}={1}; export {2}={3}; {4}'.format(
        OWNER_ENV, shlex.quote(owner), SERVICE_ENV, shlex.quote(service), command)


def owner_filter(owner):
    return 'label={0}={1}'.format(OWNER_LABEL, owner)


def service_filter(service):
    return 'label=com.docker.swarm.service.name={}'.format(service)


def owner_label(owner):
    return '{}={}'.format(OWNER_LABEL, owner)


def is_starrynet_network_name(name):
    return bool(_STARRYNET_NETWORK_NAME.match(name or ''))


def should_scope_network_create(arguments):
    """Only claim explicit StarryNet networks, never unrelated Docker nets."""
    if arguments[:3] != ['docker', 'network', 'create']:
        return False
    index = 3
    while index < len(arguments):
        argument = arguments[index]
        if argument == '--label' and index + 1 < len(arguments):
            if arguments[index + 1].split('=', 1)[0] == OWNER_LABEL:
                return True
            index += 2
            continue
        if argument.startswith('--label='):
            if argument.split('=', 1)[1].split('=', 1)[0] == OWNER_LABEL:
                return True
            index += 1
            continue
        option = argument.split('=', 1)[0]
        if option in _NETWORK_CREATE_VALUE_OPTIONS:
            index += 1 if '=' in argument else 2
            continue
        if option in _NETWORK_CREATE_FLAGS:
            index += 1
            continue
        if argument.startswith('-'):
            # Unknown Docker options make positional parsing ambiguous. Fail
            # closed: don't alter a command we cannot confidently identify.
            return False
        return is_starrynet_network_name(argument)
    return False

