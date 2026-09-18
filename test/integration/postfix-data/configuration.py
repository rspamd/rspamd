"""Validate the shipped opt-in configuration and normal include precedence."""
import json
from pathlib import Path
import subprocess


def main():
    if not Path('/.dockerenv').exists():
        raise RuntimeError('Run only inside the disposable integration image')
    root = Path('/tmp/multistage-configuration')
    (root / 'local.d').mkdir(parents=True)
    (root / 'override.d').mkdir()
    config_file = '/opt/rspamd/etc/rspamd/rspamd.conf'
    command = ['/opt/rspamd/bin/rspamadm', '--var=LOCAL_CONFDIR=' + str(root)]

    def check(expected, timeout=2):
        subprocess.run(command + ['configtest', '-c', config_file], check=True)
        result = subprocess.check_output(command + ['configdump', '-j', '-c',
                                                    config_file, 'multistage'], text=True)
        config = json.loads(result)
        assert config['enabled'] is expected and config['timeout'] == timeout, config

    check(False)
    (root / 'local.d/multistage.conf').write_text(
        'enabled = true; key = "integration-only-shared-secret-01"; timeout = 0.75s;\n')
    check(True, .75)
    (root / 'override.d/multistage.conf').write_text('enabled = false;\n')
    check(False, .75)
    (root / 'override.d/multistage.conf').unlink()
    (root / 'local.d/multistage.conf').write_text('enabled = true;\n')
    invalid = subprocess.run(command + ['configtest', '-c', config_file],
                             capture_output=True, text=True)
    assert invalid.returncode != 0, 'enabled DATA without a key must fail configtest'
    print('PASS shipped default, local.d, override.d and missing-key validation', flush=True)


if __name__ == '__main__':
    main()
