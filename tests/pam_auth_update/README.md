# PAM profile remediation integration tests

These tests change PAM configuration and create a temporary account. Run them only
in disposable containers. They are skipped unless `SSG_PAM_TEST_DISPOSABLE=1` and
the test process is root. The Dockerfile sets that variable inside the test image.
Mount the repository read-only; all authentication changes stay in the container.

Build the Debian 13 and Ubuntu 24.04 datastreams first. From the repository root:

```sh
cmake --build build --target generate-ssg-debian13-ds.xml generate-ssg-ubuntu2404-ds.xml -j 2
docker build --build-arg BASE=debian:trixie -t ssg-pam-test:debian13 tests/pam_auth_update
docker build --build-arg BASE=ubuntu:noble -t ssg-pam-test:ubuntu2404 tests/pam_auth_update

for product in debian13 ubuntu2404; do
    docker run --rm -e SSG_PAM_TEST_PRODUCT="$product" \
        -v "$PWD:/workspace:ro" "ssg-pam-test:$product" \
        python3 -m pytest -q -p no:cacheprovider \
        tests/unit/ssg-module/test_pam_auth_update.py \
        tests/pam_auth_update/test_remediations.py
done
```

The tests exercise Bash and Ansible independently, including repeated application,
existing managed profiles, conflicting stock profiles, unrelated enabled profiles,
missing faillock.conf, nondefault policy values,
reversed rule order, actual authentication and lockout/reset behavior, and OpenSCAP
results for all six rules. Additional cases exercise other rules sharing the PAM
helpers. Manual changes to the managed PAM stack must cause
remediation failure without changing the common-* files, even if debconf contains
a previous answer allowing overrides. Comments that pam-auth-update can preserve
are not treated as incompatible manual changes.

The unit tests also render all six Debian/Ubuntu versions and simulate silent
activation failures, nonzero exits, and profile-conflict messages. They do not
modify the host's PAM configuration and can run outside a container.
