#!/usr/bin/env python3
"""Install a verified bundle, backing up the current and legacy app names."""
import argparse
from datetime import datetime
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import uuid


def verify_bundle(path):
    subprocess.run(['/usr/bin/codesign', '--verify', '--deep', '--strict', str(path)], check=True)


def quit_running_app():
    def running():
        result = subprocess.run(['/usr/bin/pgrep', '-x', 'EZSwitch'], capture_output=True)
        if result.returncode not in (0, 1):
            raise RuntimeError('无法读取应用进程，安装已停止。')
        return result.returncode == 0
    if not running():
        return
    subprocess.run(['/usr/bin/osascript', '-e', 'tell application id "dev.ezswitch.app" to quit'], check=True)
    limit = time.monotonic() + 30
    while running():
        if time.monotonic() >= limit:
            raise RuntimeError('EZ Route 尚未退出。请完成应用中的退出提示后重新安装。')
        time.sleep(0.5)


def launch_bundle(path):
    subprocess.run(['/usr/bin/open', str(path)], check=True)


def install_bundle(source, destination, legacy, backups, *, verify=verify_bundle,
                   quit_app=quit_running_app, launch=launch_bundle):
    source, destination, legacy, backups = map(Path, (source, destination, legacy, backups))
    if not source.is_dir() or source.is_symlink():
        raise ValueError('构建应用不存在或路径无效。')
    destination.parent.mkdir(parents=True, exist_ok=True)
    saved = []
    with tempfile.TemporaryDirectory(prefix='.ezroute-install-', dir=destination.parent) as directory:
        staged = Path(directory) / destination.name
        subprocess.run(['/usr/bin/ditto', str(source), str(staged)], check=True)
        verify(staged)
        quit_app()
        backups.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8]
        installed = False
        try:
            for current in [destination, legacy]:
                if current.exists() or current.is_symlink():
                    backup = backups / (current.stem + '-' + stamp + '.app')
                    os.rename(current, backup)
                    saved.append((current, backup))
            os.rename(staged, destination)
            installed = True
            launch(destination)
        except BaseException as error:
            if installed:
                os.rename(destination, staged)
            for original, backup in reversed(saved):
                os.rename(backup, original)
            if saved:
                try:
                    launch(saved[0][0])
                except Exception as recovery:
                    raise RuntimeError(f'安装失败：{error}。旧应用已还原，但重新启动失败：{recovery}') from error
            raise
    return {'installed': str(destination), 'backups': [str(backup) for _, backup in saved]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--destination', type=Path, default=Path.home() / 'Applications/EZ Route.app')
    parser.add_argument('--legacy', type=Path, default=Path.home() / 'Applications/EZSwitch.app')
    parser.add_argument('--backups', type=Path, default=Path.home() / 'Applications/EZ Route Backups')
    args = parser.parse_args()
    result = install_bundle(args.source, args.destination, args.legacy, args.backups)
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
