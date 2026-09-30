#!/usr/bin/env python3
"""Clear every SOC Cloud and Threat Intelligence setting on this machine.

For testing the first-run experience: what a colleague sees on a fresh install,
where nothing is configured and the two cards in Settings are the only way in.

It touches three places, and nothing else:

  * ``~/.dsh/.credentials.yaml`` — the references the cards write (the SOC
    sign-in, both platform domains, the Threat Intelligence account) and the
    records behind them. Other credentials, such as model API keys, stay.
  * ``~/.dsh/soc-endpoints.json`` — the administrator's endpoint file.
  * The ``soc-credentials`` and ``soc-threat-intel`` sections of
    ``~/.dsh/settings.yaml``.

``--purge-legacy`` widens it to what earlier builds left behind — a retired
profile, an old backup of this script's own, and any SOC setting pinned in a
user preset or exported in the shell. Those last two are reported rather than
edited: a preset file and a shell profile are the user's own, and a script that
rewrites them silently is worse than one that says where to look.

Everything removed is copied first, so a run is undoable:

    python3 scripts/reset-soc-config.py                 # back up, then clear
    python3 scripts/reset-soc-config.py --dry-run       # say what it would clear
    python3 scripts/reset-soc-config.py --purge-legacy  # also clear what old builds left
    python3 scripts/reset-soc-config.py --restore       # put the last backup back

Quit the app first: it holds these files open and rewrites them on exit.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from datetime import datetime
from pathlib import Path

try:
    import yaml
except ModuleNotFoundError:  # pragma: no cover - environment guard
    sys.exit('reset-soc-config: this needs PyYAML (pip3 install pyyaml).')

#: Credential references the two cards write. Anything else in the store is
#: someone else's and is left alone.
SOC_REFS = (
    'SOC_USERNAME',
    'SOC_PASSWORD',
    'SOC_DOMAIN',
    'SOC_CLIENT_ID',
    'SOC_TENANT',
    'SOC_IAM_URL',
    'SOC_REDIRECT_URI',
    'SOC_SOAR_BASE_URL',
    'SOC_SOAR_CLIENT_ID',
    'SOC_EDR_BASE_URL',
    'SOC_EDR_CLIENT_ID',
    'SOC_SIEM_BASE_URL',
    'SOC_SIEM_CLIENT_ID',
    'SOC_NSM_BASE_URL',
    'SOC_NSM_CLIENT_ID',
    'TI_DOMAIN',
    'TI_USERNAME',
    'TI_API_KEY',
)

#: Settings sections the two cards are keyed to.
SOC_SECTIONS = ('soc-credentials', 'soc-threat-intel')

BACKUP_PREFIX = 'soc-reset-backup-'

#: Environment variables that outrank the cards: a value exported here is read
#: before anything the user types, so a stale one makes a corrected setting look
#: ignored. Reported, never unset — this process cannot change its parent shell.
LEGACY_ENV_PREFIXES = ('SOC_', 'TI_')

#: Shell files an earlier setup may have exported those from.
SHELL_FILES = ('.zshrc', '.zshenv', '.zprofile', '.bash_profile', '.bashrc', '.profile')


def legacy_env() -> list[str]:
    """SOC and Threat Intelligence variables exported in this environment.

    :returns: the variable names, without their values.
    """
    return sorted(
        name for name in os.environ
        if name.startswith(LEGACY_ENV_PREFIXES) and name != 'TI_'
    )


def legacy_shell_files() -> list[Path]:
    """Shell start-up files that mention one of those variables.

    :returns: the files to look in, never their contents.
    """
    found = []
    for name in SHELL_FILES:
        path = Path.home() / name
        if not path.exists():
            continue
        try:
            text = path.read_text(encoding='utf8', errors='replace')
        except OSError:
            continue
        if any(f'{prefix}' in text for prefix in ('SOC_', 'TI_DOMAIN', 'TI_USERNAME', 'TI_API_KEY')):
            found.append(path)
    return found


def legacy_presets(home: Path) -> list[Path]:
    """User presets that pin a SOC setting in their own ``config:`` block.

    A preset row outranks every other source, so one left over from an earlier
    build keeps pointing the tools at an address the cards cannot correct.

    :param home: the Harness home.
    :returns: the preset files that mention one.
    """
    root = home / '.agent-presets'
    if not root.is_dir():
        return []
    keys = ('socDomain', 'clientId', 'iamUrl', 'redirectUri', 'soarBaseUrl', 'edrBaseUrl',
            'siemBaseUrl', 'nsmBaseUrl', 'tenant')
    found = []
    for path in sorted(root.glob('*/*.yml')):
        try:
            text = path.read_text(encoding='utf8', errors='replace')
        except OSError:
            continue
        if any(f'{key}:' in text for key in keys):
            found.append(path)
    return found


def legacy_directories(home: Path) -> list[Path]:
    """Directories an earlier build or an earlier run of this script left.

    :param home: the Harness home.
    :returns: retired profiles and this script's own older backups.
    """
    retired = sorted(p for p in (home / 'profiles').glob('*.old') if p.is_dir())
    backups = sorted(p for p in home.glob(f'{BACKUP_PREFIX}*') if p.is_dir())
    return retired + backups


def dsh_home() -> Path:
    """The Harness home this machine uses.

    :returns: ``$DSH_HOME`` when set, otherwise ``~/.dsh``.
    """
    configured = os.environ.get('DSH_HOME', '').strip()
    return Path(configured) if configured else Path.home() / '.dsh'


def load_yaml(path: Path) -> dict:
    """Read a YAML mapping, treating an absent or empty file as ``{}``.

    :param path: the file to read.
    :returns: the mapping.
    """
    if not path.exists():
        return {}
    loaded = yaml.safe_load(path.read_text(encoding='utf8'))
    return loaded if isinstance(loaded, dict) else {}


def plan(home: Path) -> tuple[list[str], list[str], bool]:
    """Work out what a reset would clear, without changing anything.

    :param home: the Harness home.
    :returns: the credential references, the settings sections, and whether the
        endpoints file is present.
    """
    credentials = load_yaml(home / '.credentials.yaml')
    refs = [ref for ref in SOC_REFS if ref in (credentials.get('refs') or {})]
    settings = load_yaml(home / 'settings.yaml')
    sections = [section for section in SOC_SECTIONS if section in settings]
    return refs, sections, (home / 'soc-endpoints.json').exists()


def backup(home: Path) -> Path:
    """Copy every file a reset may touch into a timestamped directory.

    :param home: the Harness home.
    :returns: the backup directory.
    """
    directory = home / f'{BACKUP_PREFIX}{datetime.now():%Y%m%d-%H%M%S}'
    directory.mkdir(parents=True)
    for name in ('.credentials.yaml', 'settings.yaml', 'soc-endpoints.json'):
        source = home / name
        if source.exists():
            shutil.copy2(source, directory / name)
    return directory


def clear_credentials(home: Path, refs: list[str]) -> None:
    """Drop the SOC references and any record left with nothing pointing at it.

    :param home: the Harness home.
    :param refs: the references to remove.
    """
    path = home / '.credentials.yaml'
    store = load_yaml(path)
    if not store:
        return
    references = store.get('refs') or {}
    removed_ids = {references.pop(ref) for ref in refs if ref in references}
    store['refs'] = references
    # A record outlives its reference otherwise, holding a secret nothing can
    # read but the file still carries.
    kept = set(references.values())
    records = store.get('records') or {}
    store['records'] = {
        record_id: record for record_id, record in records.items()
        if record_id not in removed_ids or record_id in kept
    }
    path.write_text(yaml.safe_dump(store, sort_keys=False, allow_unicode=True), encoding='utf8')
    path.chmod(0o600)


def clear_settings(home: Path, sections: list[str]) -> None:
    """Remove the two cards' settings sections.

    :param home: the Harness home.
    :param sections: the sections to remove.
    """
    path = home / 'settings.yaml'
    settings = load_yaml(path)
    for section in sections:
        settings.pop(section, None)
    path.write_text(yaml.safe_dump(settings, sort_keys=False, allow_unicode=True), encoding='utf8')
    path.chmod(0o600)


def latest_backup(home: Path) -> Path | None:
    """The most recent backup directory, if there is one.

    :param home: the Harness home.
    :returns: the directory, or ``None``.
    """
    directories = sorted(home.glob(f'{BACKUP_PREFIX}*'))
    return directories[-1] if directories else None


def restore(home: Path) -> int:
    """Put the most recent backup back.

    :param home: the Harness home.
    :returns: the process exit code.
    """
    directory = latest_backup(home)
    if directory is None:
        print(f'reset-soc-config: no backup under {home}', file=sys.stderr)
        return 1
    for source in directory.iterdir():
        target = home / source.name
        shutil.copy2(source, target)
        target.chmod(0o600)
        print(f'restored: {target}')
    # A file the backup does not hold was absent when it was taken.
    for name in ('soc-endpoints.json',):
        if not (directory / name).exists() and (home / name).exists():
            (home / name).unlink()
            print(f'removed: {home / name} (absent in the backup)')
    return 0


def report_legacy(variables: list[str], shell_files: list[Path], presets: list[Path]) -> None:
    """Name what this script will not touch but that still overrides the cards.

    :param variables: SOC and Threat Intelligence variables in this environment.
    :param shell_files: shell start-up files that mention one.
    :param presets: user presets that pin a SOC setting.
    """
    if not variables and not shell_files and not presets:
        return
    print('\nLeft in place, and read BEFORE anything typed in the app:')
    if variables:
        print(f'  environment: {", ".join(variables)}')
        print('    unset them in the shell that starts the app, or remove the export below.')
    for path in shell_files:
        print(f'  shell file: {path} — mentions SOC_/TI_; edit it yourself.')
    for path in presets:
        print(f'  preset: {path} — pins a SOC setting in its config block; edit it yourself.')


def main() -> int:
    """Run the reset, the dry run, or the restore.

    :returns: the process exit code.
    """
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--dry-run', action='store_true', help='say what would be cleared')
    parser.add_argument(
        '--purge-legacy', action='store_true',
        help='also clear what earlier builds left: retired profiles and older backups',
    )
    parser.add_argument('--restore', action='store_true', help='put the most recent backup back')
    arguments = parser.parse_args()

    home = dsh_home()
    if not home.exists():
        print(f'reset-soc-config: no Harness home at {home}', file=sys.stderr)
        return 1
    if arguments.restore:
        return restore(home)

    refs, sections, endpoints = plan(home)
    directories = legacy_directories(home) if arguments.purge_legacy else []
    # Always surveyed, whatever the mode: these outrank the cards, so a machine
    # carrying one has a setting the user cannot correct from the app, and
    # saying so is the whole point of running this.
    variables, shell_files, presets = legacy_env(), legacy_shell_files(), legacy_presets(home)
    if not refs and not sections and not endpoints and not directories:
        print(f'Nothing to clear: {home} holds no SOC or Threat Intelligence configuration.')
        report_legacy(variables, shell_files, presets)
        return 0

    print(f'Harness home: {home}')
    if refs:
        print(f'  credentials to clear ({len(refs)}): {", ".join(refs)}')
    if sections:
        print(f'  settings sections to clear: {", ".join(sections)}')
    if endpoints:
        print('  endpoints file to remove: soc-endpoints.json')
    for directory in directories:
        print(f'  directory to remove: {directory.relative_to(home)}')
    if arguments.dry_run:
        print('\nDry run: nothing was changed.')
        report_legacy(variables, shell_files, presets)
        return 0

    directory = backup(home)
    print(f'\nbacked up to: {directory}')
    if refs:
        clear_credentials(home, refs)
        print('cleared: credential references')
    if sections:
        clear_settings(home, sections)
        print('cleared: settings sections')
    if endpoints:
        (home / 'soc-endpoints.json').unlink()
        print('removed: soc-endpoints.json')
    for target in directories:
        # The fresh backup is taken before this runs and is not in the list,
        # so an undo is still possible after a purge.
        shutil.rmtree(target)
        print(f'removed: {target.relative_to(home)}')
    print('\nStart the app and configure it from Settings → Plugins.')
    print(f'To undo: python3 {Path(__file__).name} --restore')
    report_legacy(variables, shell_files, presets)
    return 0


if __name__ == '__main__':
    sys.exit(main())
