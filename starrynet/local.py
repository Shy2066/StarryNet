"""Local equivalents of the SSH command and SFTP interfaces used by StarryNet."""
from pathlib import Path
import json
import os
import shlex
import shutil
import subprocess
import sys
import time

from starrynet.resource_scope import (
    owner_label, resource_identity, should_scope_network_create)


class LocalExecutor:
    is_local_executor = True

    def __init__(self, root):
        self.root = Path(root).resolve()
        self.env_overrides = {}

    def run(self, command, allowed_returncodes=(0,),
            include_stderr_on_failure=True):
        # Upstream assumes SSH starts in ~. Keep local files inside this run.
        command = command.replace('~/', './')
        if command.startswith('mkdir '):
            command = command.replace('mkdir ', 'mkdir -p ', 1)
        if command.startswith('python3 '):
            command = shlex.quote(sys.executable) + command[len('python3'):]
        started_ns = int(time.monotonic() * 1e9)
        environment = os.environ.copy()
        environment.update(self.env_overrides)
        # Scope network creation even when it comes from an older helper that
        # does not pass through sn_orchestrater.sn_checked_system.
        arguments = shlex.split(command)
        if should_scope_network_create(arguments):
            owner, _service = resource_identity(environment)
            cleaned = []
            index = 3
            while index < len(arguments):
                if arguments[index] == '--label' and index + 1 < len(arguments):
                    label = arguments[index + 1]
                    if label.split('=', 1)[0] != 'starrynet.owner':
                        cleaned.extend(arguments[index:index + 2])
                    index += 2
                    continue
                cleaned.append(arguments[index])
                index += 1
            arguments = arguments[:3] + cleaned
            arguments[3:3] = ['--label', owner_label(owner)]
            if environment.get('STARRYNET_DISABLE_MASQUERADE') == '1':
                if 'com.docker.network.bridge.enable_ip_masquerade=true' in arguments:
                    raise ValueError('Replay network explicitly enables masquerade')
                if 'com.docker.network.bridge.enable_ip_masquerade=false' not in arguments:
                    arguments.extend(['--opt',
                                      'com.docker.network.bridge.enable_ip_masquerade=false'])
            command = ' '.join(shlex.quote(part) for part in arguments)
        result = subprocess.run(command, shell=True, executable='/bin/bash',
                                cwd=self.root, universal_newlines=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=600, env=environment)
        finished_ns = int(time.monotonic() * 1e9)
        with (self.root / 'commands.jsonl').open('a') as log:
            log.write(json.dumps({
                'command': command, 'start_monotonic_ns': started_ns,
                'end_monotonic_ns': finished_ns, 'returncode': result.returncode,
                'clock_domain': 'CLOCK_MONOTONIC',
                'env_overrides': dict(self.env_overrides),
            }, sort_keys=True) + '\n')
        with (self.root / 'commands.log').open('a') as log:
            log.write(f'$ {command}\n{result.stdout}{result.stderr}\n')
        if result.returncode not in allowed_returncodes:
            raise RuntimeError(f'Local command failed ({result.returncode}): '
                               f'{command}\n{result.stderr}{result.stdout}')
        output = result.stdout
        if result.returncode and include_stderr_on_failure:
            output += result.stderr
        return output.splitlines(keepends=True)

    def close(self):
        pass


class LocalFiles:
    def __init__(self, root):
        self.root = Path(root).resolve()

    def put(self, source, destination):
        target = (self.root / destination).resolve()
        if self.root not in target.parents and target != self.root:
            raise ValueError('Local destination escapes the run directory')
        target.parent.mkdir(parents=True, exist_ok=True)
        if Path(source).resolve() != target:
            shutil.copy2(source, target)

    def close(self):
        pass
