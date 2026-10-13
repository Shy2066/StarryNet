"""Local equivalents of the SSH command and SFTP interfaces used by StarryNet."""
from pathlib import Path
import shlex
import shutil
import subprocess
import sys


class LocalExecutor:
    def __init__(self, root):
        self.root = Path(root).resolve()

    def run(self, command, allowed_returncodes=(0,)):
        # Upstream assumes SSH starts in ~. Keep local files inside this run.
        command = command.replace('~/', './')
        if command.startswith('mkdir '):
            command = command.replace('mkdir ', 'mkdir -p ', 1)
        if command.startswith('python3 '):
            command = shlex.quote(sys.executable) + command[len('python3'):]
        result = subprocess.run(command, shell=True, executable='/bin/bash',
                                cwd=self.root, universal_newlines=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=600)
        with (self.root / 'commands.log').open('a') as log:
            log.write(f'$ {command}\n{result.stdout}{result.stderr}\n')
        if result.returncode not in allowed_returncodes:
            raise RuntimeError(f'Local command failed ({result.returncode}): '
                               f'{command}\n{result.stderr}{result.stdout}')
        output = result.stdout + (result.stderr if result.returncode else '')
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
