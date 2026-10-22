"""Bounded Podman execution and read-only resource ownership inspection."""
import json
import subprocess
from typing import Sequence

from .paths import ProfileIdentity

LABEL_PREFIX = 'io.t3-sandbox.'
ROLES = frozenset(('t3', 'proxy', 'private', 'external'))


def resource_labels(resource: dict) -> dict:
    """Containers/images use Config.Labels; Netavark networks use labels."""
    return resource.get('Config', {}).get('Labels') or resource.get('labels') or resource.get('Labels') or {}


def published_bindings(resource: dict) -> dict:
    """Podman normalizes an IPv4 wildcard bind to the empty HostIp string."""
    return {port: [dict(binding, HostIp='0.0.0.0' if binding.get('HostIp') == '' else binding.get('HostIp'))
                   for binding in bindings]
            for port, bindings in (resource.get('HostConfig', {}).get('PortBindings') or {}).items() if bindings}


def assert_owned(resource: dict, identity: ProfileIdentity) -> None:
    labels = resource_labels(resource)
    expected = {'managed': 'true', 'uid': str(identity.uid), 'profile': identity.name}
    if any(labels.get(LABEL_PREFIX + key) != value for key, value in expected.items()) or labels.get(LABEL_PREFIX + 'role') not in ROLES:
        raise ValueError(f'Refusing unowned resource for profile {identity.name}')


class Podman:
    def run(self, args: Sequence[str], *, check=True, timeout=30, capture=True) -> subprocess.CompletedProcess[str]:
        return subprocess.run(['podman', *args], check=check, timeout=timeout,
                              capture_output=capture, text=True)

    def inspect(self, kind: str, name: str) -> dict | None:
        if kind not in ('container', 'network', 'image'):
            raise ValueError(f'Unsupported Podman resource kind: {kind}')
        # The exists commands document status 1 for absence. Do not classify
        # arbitrary inspect stderr strings or every status 125 as "not found".
        exists = self.run([kind, 'exists', name], check=False)
        if exists.returncode == 1:
            return None
        exists.check_returncode()
        result = self.run([kind, 'inspect', name])
        try:
            values = json.loads(result.stdout)
        except (ValueError, TypeError) as exc:
            raise ValueError(f'Invalid Podman {kind} inspection JSON') from exc
        if not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], dict):
            raise ValueError(f'Expected one Podman {kind} inspection object')
        return values[0]

    def inspect_owned(self, kind: str, name: str, identity: ProfileIdentity, *, role: str | None = None) -> dict | None:
        expected_roles = {
            'container': {identity.container: 't3', identity.proxy: 'proxy'},
            'network': {identity.private_network: 'private', identity.external_network: 'external'},
            'image': {identity.image: 't3', identity.proxy_image: 'proxy'},
        }
        expected_role = expected_roles.get(kind, {}).get(name)
        if expected_role is None or role is not None and role != expected_role:
            raise ValueError(f'Resource name or role does not match profile {identity.name}')
        resource = self.inspect(kind, name)
        if resource is not None:
            assert_owned(resource, identity)
            if resource_labels(resource).get(LABEL_PREFIX + 'role') != expected_role:
                raise ValueError(f'Resource has wrong role for profile {identity.name}: expected {expected_role}')
        return resource

    def inspect_containers(self, *, managed_only=False) -> list[dict]:
        filters = ['--filter', f'label={LABEL_PREFIX}managed=true'] if managed_only else []
        result = self.run(['ps', '-a', *filters, '--format', 'json'])
        try:
            values = json.loads(result.stdout)
        except (ValueError, TypeError) as exc:
            raise ValueError('Invalid Podman container listing JSON') from exc
        if not isinstance(values, list) or any(not isinstance(item, dict) or not isinstance(item.get('Id'), str) for item in values):
            raise ValueError('Invalid Podman container listing')
        containers = []
        for item in values:
            resource = self.inspect('container', item['Id'])
            if resource is not None and (not managed_only or resource_labels(resource).get(LABEL_PREFIX + 'managed') == 'true'):
                containers.append(resource)
        return containers

    def managed_containers(self) -> list[dict]:
        return self.inspect_containers(managed_only=True)
