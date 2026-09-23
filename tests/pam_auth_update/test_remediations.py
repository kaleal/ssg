"""Destructive integration tests: run ONLY in a disposable Debian/Ubuntu container.

See README.md in this directory. Ordinary pytest runs skip this module.
"""
import importlib.util
import os
from pathlib import Path
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET

import pytest
import yaml

pytestmark = pytest.mark.skipif(
    os.environ.get('SSG_PAM_TEST_DISPOSABLE') != '1' or os.geteuid() != 0,
    reason='requires an explicitly disposable root test environment')
ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    'pam_render_tests', ROOT / 'tests/unit/ssg-module/test_pam_auth_update.py')
renderer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(renderer)
PRODUCT = os.environ.get('SSG_PAM_TEST_PRODUCT', 'ubuntu2404')
RULES = ['pwhistory', 'pwquality', 'deny', 'unlock_time', 'root_unlock_time', 'enabled']
VALUES = {'var_password_pam_remember': 32,
          'var_accounts_passwords_pam_faillock_deny': 2,
          'var_accounts_passwords_pam_faillock_unlock_time': 1200,
          'var_accounts_passwords_pam_faillock_root_unlock_time': 1200}
IDS = {'pwhistory': 'accounts_password_pam_pwhistory_remember',
       'pwquality': 'accounts_password_pam_pwquality_enabled',
       'enabled': 'accounts_passwords_pam_faillock_enabled',
       **{name: 'accounts_passwords_pam_faillock_' + name for name in ['deny', 'unlock_time', 'root_unlock_time']}}


def run(command, **kwargs):
    return subprocess.run(command, text=True, capture_output=True, timeout=180, **kwargs)


def require_success(result):
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.fixture(autouse=True)
def restore_pam(tmp_path):
    paths = ['/etc/pam.d', '/usr/share/pam-configs', '/var/lib/pam',
             '/var/cache/debconf', '/etc/security/faillock.conf']
    for i, path in enumerate(paths):
        source = Path(path)
        if source.is_dir():
            shutil.copytree(source, tmp_path / str(i))
        elif source.exists():
            shutil.copy2(source, tmp_path / str(i))
    yield
    for i, path in enumerate(paths):
        target = Path(path)
        if target.is_dir():
            shutil.rmtree(target)
        elif target.exists():
            target.unlink()
        saved = tmp_path / str(i)
        if saved.is_dir():
            shutil.copytree(saved, target)
        elif saved.exists():
            shutil.copy2(saved, target)


def apply(engine, rules, tmp_path, syntax_only=False):
    if engine == 'bash':
        script = '\n'.join(renderer.render(PRODUCT, rule, 'bash') for rule in rules)
        script = re.sub(r"'\(bash-populate ([^)]+)\)'", lambda m: str(VALUES[m[1]]), script)
        return run(['bash', '-n' if syntax_only else '-s'], input=script)
    tasks = []
    for rule in rules:
        tasks.extend(task for task in yaml.safe_load(renderer.render(PRODUCT, rule, 'ansible'))
                     if isinstance(task, dict))
    play = [{'hosts': 'localhost', 'gather_facts': False, 'vars': VALUES, 'tasks': tasks}]
    playbook = tmp_path / 'play.yml'
    playbook.write_text(yaml.safe_dump(play, sort_keys=False))
    command = ['ansible-playbook', '-i', 'localhost,', '-c', 'local', str(playbook)]
    if syntax_only:
        command.append('--syntax-check')
    return run(command)


def common_files():
    return {str(path): path.read_bytes() for path in Path('/etc/pam.d').glob('common-*')}


@pytest.mark.parametrize('engine', ['bash', 'ansible'])
@pytest.mark.parametrize('rule', RULES)
def test_individual_rule_and_repeat(engine, rule, tmp_path):
    require_success(apply(engine, [rule], tmp_path, syntax_only=True))
    require_success(apply(engine, [rule], tmp_path))
    first = common_files()
    again = apply(engine, [rule], tmp_path)
    require_success(again)
    assert common_files() == first
    if engine == 'ansible':
        assert 'changed=0' in again.stdout


@pytest.mark.parametrize('engine', ['bash', 'ansible'])
def test_combined_authentication_and_oval(engine, tmp_path):
    require_success(apply(engine, RULES, tmp_path))
    first = common_files()
    require_success(apply(engine, list(reversed(RULES)), tmp_path))
    assert common_files() == first
    # Reapplying the manager itself must not detect local modifications.
    result = run(['pam-auth-update', '--package'], env=dict(os.environ, DEBIAN_FRONTEND='noninteractive', LC_ALL='C'))
    require_success(result)
    assert 'Local modifications' not in result.stderr
    assert common_files() == first
    # Test the actual PAM stack, including the account stage used to reset failures.
    service = Path('/etc/pam.d/ssg-pam-test')
    service.write_text('@include common-auth\n@include common-account\n')
    username = 'ssgpamtest'
    run(['userdel', username])
    require_success(run(['useradd', '-m', username]))
    password = 'Temporary-PAM-test-93!'
    require_success(run(['chpasswd'], input=username + ':' + password + '\n'))
    def authenticate(secret):
        return run(['pamtester', 'ssg-pam-test', username, 'authenticate', 'acct_mgmt'], input=secret + '\n')
    try:
        require_success(authenticate(password))
        assert authenticate('incorrect').returncode != 0
        require_success(authenticate(password))  # Resets the first failed attempt.
        assert authenticate('incorrect').returncode != 0
        require_success(authenticate(password))
        assert authenticate('incorrect').returncode != 0
        assert authenticate('incorrect').returncode != 0
        assert authenticate(password).returncode != 0  # Locked out at deny=2.
        require_success(run(['faillock', '--user', username, '--reset']))
        require_success(authenticate(password))
    finally:
        run(['userdel', '-r', username])
    ds = ROOT / 'build' / ('ssg-' + PRODUCT + '-ds.xml')
    assert ds.exists(), 'Build the product datastream before running the integration tests'
    for rule in RULES:
        result_file = tmp_path / (rule + '.xml')
        result = run(['oscap', 'xccdf', 'eval', '--profile', 'cis_level2_server',
                      '--rule', 'xccdf_org.ssgproject.content_rule_' + IDS[rule],
                      '--results', str(result_file), str(ds)])
        require_success(result)
        ns = {'x': 'http://checklists.nist.gov/xccdf/1.2'}
        results = ET.parse(result_file).findall('.//x:rule-result', ns)
        matching = [r for r in results if r.get('idref').endswith('_' + IDS[rule])]
        assert len(matching) == 1
        assert matching[0].find('x:result', ns).text == 'pass', result.stdout + result.stderr


@pytest.mark.parametrize('engine', ['bash', 'ansible'])
@pytest.mark.parametrize('rule', RULES)
def test_manual_edits_are_preserved(engine, rule, tmp_path):
    path = Path('/etc/pam.d/common-auth')
    path.write_text(path.read_text().replace('# here are the per-package modules (the \"Primary\" block)\n', '# here are the per-package modules (the \"Primary\" block)\nauth required pam_debug.so auth=success\n'))
    before = common_files()
    # Even a stale debconf answer must not authorize replacement.
    require_success(run(['debconf-set-selections'], input='libpam-runtime libpam-runtime/override boolean true\n'))
    result = apply(engine, [rule], tmp_path)
    assert result.returncode != 0, result.stdout + result.stderr
    assert 'local' in (result.stdout + result.stderr).lower()
    assert common_files() == before


@pytest.mark.parametrize('engine', ['bash', 'ansible'])
def test_existing_profiles_and_missing_faillock_config(engine, tmp_path):
    require_success(apply(engine, RULES, tmp_path))
    history = Path('/usr/share/pam-configs/cac_pwhistory')
    history.write_text(history.read_text().replace('remember=32', 'remember=9 debug').replace(' use_authtok', ''))
    for profile in ['cac_faillock', 'cac_faillock_notify']:
        path = Path('/usr/share/pam-configs') / profile
        path.write_text(path.read_text().replace('pam_faillock.so', 'pam_faillock.so deny=9 unlock_time=5 root_unlock_time=5'))
    Path('/etc/security/faillock.conf').unlink()
    require_success(apply(engine, RULES, tmp_path))
    assert history.read_text().count('remember=32') == 2
    assert history.read_text().count('debug') == 2
    for profile in ['cac_faillock', 'cac_faillock_notify']:
        assert 'deny=' not in (Path('/usr/share/pam-configs') / profile).read_text()
    first = common_files()
    require_success(apply(engine, RULES, tmp_path))
    assert common_files() == first


@pytest.mark.parametrize('engine', ['bash', 'ansible'])
def test_stock_conflicts_and_unrelated_profile(engine, tmp_path):
    # Simulate stock alternatives even on releases that do not ship all of them.
    import ssg.jinja
    for profile in ['pwhistory', 'pwquality', 'faillock', 'faillock_notify']:
        path = Path('/usr/share/pam-configs') / profile
        if not path.exists():
            template = tmp_path / 'profile.jinja'
            template.write_text("{{{ pam_auth_update_profile('cac_" + profile + "') }}}")
            content = ssg.jinja.process_file(str(template), {'product': PRODUCT})
            content = re.sub(r'^Conflicts:.*\n', '', content, flags=re.M)
            path.write_text(content)
    extra = Path('/usr/share/pam-configs/ssg_unrelated')
    extra.write_text('Name: Unrelated test profile\nDefault: no\nPriority: 1\n'
                     'Session-Type: Additional\nSession: optional pam_permit.so\n')
    result = run(['pam-auth-update', '--enable', 'pwhistory', 'pwquality', 'faillock',
                  'faillock_notify', 'ssg_unrelated'],
                 env=dict(os.environ, DEBIAN_FRONTEND='noninteractive', LC_ALL='C'))
    require_success(result)
    sessions = Path('/etc/pam.d/common-session').read_bytes()
    require_success(apply(engine, RULES, tmp_path))
    assert Path('/etc/pam.d/common-session').read_bytes() == sessions
    assert extra.exists()
    first = common_files()
    require_success(apply(engine, RULES, tmp_path))
    assert common_files() == first


def test_other_bash_helper_callers(tmp_path):
    # Shared helpers must still support the existing enable/enforce-root rules
    # and parameter-only faillock rules that use the same profiles.
    require_success(apply('bash', RULES, tmp_path))
    rules = ['accounts_password_pam_pwhistory_enforce_root',
             'accounts_passwords_pam_faillock_silent']
    if PRODUCT.startswith('debian'):
        rules.append('accounts_passwords_pam_faillock_deny_root')
    else:
        rules.append('accounts_passwords_pam_faillock_audit')
    for rule in rules:
        script = ROOT / 'build' / PRODUCT / 'fixes/bash' / (rule + '.sh')
        assert script.exists(), script
        require_success(run(['bash', str(script)]))
    before = common_files()
    result = run(['pam-auth-update', '--package'],
                 env=dict(os.environ, DEBIAN_FRONTEND='noninteractive', LC_ALL='C'))
    require_success(result)
    assert 'Local modifications' not in result.stderr
    assert common_files() == before
