"""Profile rendering and error handling for Debian/Ubuntu PAM remediations."""
import os
from pathlib import Path
import re
import subprocess

import pytest
import yaml

import ssg.jinja

ROOT = Path(__file__).resolve().parents[3]
PRODUCTS = ['debian11', 'debian12', 'debian13', 'ubuntu2204', 'ubuntu2404', 'ubuntu2604']
BASE = ROOT / 'linux_os/guide/system/accounts/accounts-pam'
RULES = {
    'enabled': BASE / 'locking_out_password_attempts/accounts_passwords_pam_faillock_enabled',
    'pwhistory': BASE / 'locking_out_password_attempts/accounts_password_pam_pwhistory_remember',
    'pwquality': BASE / 'password_quality/password_quality_pwquality/accounts_password_pam_pwquality_enabled',
}


def render(product, rule, language):
    env = dict(product=product, rule_id=rule, rule_title=rule,
               pam_faillock_conf_path='/etc/security/faillock.conf',
               PRM_NAME=rule, EXT_VARIABLE='var_accounts_passwords_pam_faillock_' + rule)
    if rule in RULES:
        source = RULES[rule] / language / ('shared.sh' if language == 'bash' else 'shared.yml')
    else:
        source = ROOT / 'shared/templates/pam_account_password_faillock' / (language + '.template')
    return ssg.jinja.process_file(str(source), env)


@pytest.mark.parametrize('product', PRODUCTS)
@pytest.mark.parametrize('rule', ['pwhistory', 'pwquality', 'deny', 'unlock_time', 'root_unlock_time', 'enabled'])
def test_render_profile_remediations(product, rule):
    bash = render(product, rule, 'bash')
    subprocess.run(['bash', '-n'], input=bash, text=True, check=True)
    tasks = yaml.safe_load(render(product, rule, 'ansible'))
    assert tasks
    assert 'pam-auth-update --disable' in bash
    assert 'pam-auth-update --force' not in bash
    assert 'sed -i' not in '\n'.join(line for line in bash.splitlines() if '/etc/pam.d/' in line)
    assert '"$pam_file"' not in bash  # No indirect edits to generated PAM files.


def test_history_ansible_preserves_options_and_is_idempotent():
    tasks = yaml.safe_load(render('debian13', 'pwhistory', 'ansible'))
    replacements = [task['ansible.builtin.replace'] for task in tasks
                    if isinstance(task, dict) and 'ansible.builtin.replace' in task]
    content = ('Password: requisite pam_pwhistory.so debug remember=12 use_authtok\n'
               'Password-Initial: requisite pam_pwhistory.so remember=12 debug\n')
    def apply(text):
        for task in replacements:
            replacement = task['replace'].replace('{{ var_password_pam_remember }}', '32')
            text = re.sub(task['regexp'], replacement, text)
        return text
    updated = apply(content)
    assert updated.count('remember=32') == 2
    assert updated.count('debug') == 2
    assert updated.count('use_authtok') == 1
    assert apply(updated) == updated


@pytest.mark.parametrize('output,status,valid,success', [
    ('', 0, True, True),
    ('pam-auth-update: Local modifications to /etc/pam.d/common-*, not updating.', 0, True, False),
    ('Incompatible PAM profiles selected.', 0, True, False),
    ('unexpected failure', 1, True, False),
    ('', 0, False, False),
])
def test_activation_checks_output_and_generated_files(tmp_path, output, status, valid, success):
    template = tmp_path / 'activate.jinja'
    template.write_text("{{{ bash_apply_pam_auth_update(['cac_pwquality'], ['cracklib', 'pwquality']) }}}")
    script = ssg.jinja.process_file(str(template), {'product': 'debian13'})
    pam = tmp_path / 'common-password'
    pam.write_text('password requisite pam_pwquality.so\n' if valid else '# missing module\n')
    before = pam.read_bytes()
    script = script.replace('/etc/pam.d/common-password', str(pam))
    commands = tmp_path / 'bin'
    commands.mkdir()
    for name, body in {
        'debconf-set-selections': 'cat >/dev/null\n',
        'pam-auth-update': 'printf "%s\\n" "$PAM_TEST_OUTPUT"\nexit "$PAM_TEST_STATUS"\n',
    }.items():
        command = commands / name
        command.write_text('#!/bin/sh\n' + body)
        command.chmod(0o755)
    env = dict(os.environ, PATH=str(commands) + ':' + os.environ['PATH'],
               PAM_TEST_OUTPUT=output, PAM_TEST_STATUS=str(status))
    result = subprocess.run(['bash'], input=script, text=True, capture_output=True, env=env)
    assert (result.returncode == 0) == success, result.stdout + result.stderr
    assert pam.read_bytes() == before
