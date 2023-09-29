local docker_pipeline = {
  kind: 'pipeline',
  type: 'docker',
};

local default_trigger = {
  trigger: {
    event: [
      'push',
      'tag',
      'pull_request',
      'custom',
    ],
  },
};

local platform(arch) = {
  platform: {
    os: 'linux',
    arch: arch,
  },
};

local coveralls_attribs = {
  branch: [
    'master',
  ],
  event: [
    'push',
    'tag',
  ],
};

local coveralls_trigger = {
  trigger: coveralls_attribs,
};

local coveralls_when = {
  when: coveralls_attribs,
};

local notify_pipeline = {
  name: 'notify',
  depends_on: [
    'default-amd64',
    'default-arm64',
    'default-noarch',
  ],
  steps: [
    {
      name: 'notify',
      image: 'drillster/drone-email',
      pull: 'if-not-exists',
      settings: {
        from: 'noreply@rspamd.com',
        host: {
          from_secret: 'email_host',
        },
        username: {
          from_secret: 'email_username',
        },
        password: {
          from_secret: 'email_password',
        },
      },
    },
  ],
  trigger: {
    status: [
      'failure',
    ],
  },
} + docker_pipeline;

local pipeline(arch) = {
  local rspamd_volumes = {
    volumes: [
      {
        name: 'rspamd',
        path: '/rspamd',
      },
    ],
  },
  local hyperscan_altroot = if (arch) == 'amd64' then '' else '-DHYPERSCAN_ROOT_DIR=/vectorscan',
  depends_on: [
  ],
  name: 'default-' + arch,
  steps: [
    {
      name: 'prepare',
      image: 'ubuntu:22.04',
      pull: 'if-not-exists',
      commands: [
        'install -d -o nobody -g nogroup /rspamd/build /rspamd/install /rspamd/fedora/build /rspamd/fedora/install',
      ],
    } + rspamd_volumes,
    {
      name: 'build',
      image: 'rspamd/ci:ubuntu-build',
      pull: 'always',
      depends_on: [
        'prepare',
      ],
      commands: [
        'test "$(id -un)" = nobody',
        'cd /rspamd/build',
        'cmake -DCMAKE_INSTALL_PREFIX=/rspamd/install -DCMAKE_RULE_MESSAGES=OFF -DCMAKE_VERBOSE_MAKEFILE=ON -DENABLE_COVERAGE=ON -DENABLE_LIBUNWIND=ON -DENABLE_HYPERSCAN=ON ' + hyperscan_altroot + ' -GNinja $DRONE_WORKSPACE\n',
        'ncpu=$(getconf _NPROCESSORS_ONLN)',
        'ninja -j $ncpu install',
        'ninja -j $ncpu rspamd-test',
        'ninja -j $ncpu rspamd-test-cxx',
      ],
    } + rspamd_volumes,
    {
      name: 'build-clang',
      image: 'rspamd/ci:fedora-build',
      pull: 'always',
      depends_on: [
        'prepare',
      ],
      commands: [
        'test "$(id -un)" = nobody',
        'cd /rspamd/fedora/build',
        "export LDFLAGS='-fuse-ld=lld'",
        'export ASAN_OPTIONS=detect_leaks=0',
        'cmake -DCMAKE_INSTALL_PREFIX=/rspamd/fedora/install -DCMAKE_C_COMPILER=/usr/bin/clang -DCMAKE_CXX_COMPILER=/usr/bin/clang++ -DCMAKE_RULE_MESSAGES=OFF -DCMAKE_VERBOSE_MAKEFILE=ON -DENABLE_CLANG_PLUGIN=ON -DENABLE_FULL_DEBUG=ON -DENABLE_HYPERSCAN=ON ' + hyperscan_altroot + ' -DSANITIZE=address $DRONE_WORKSPACE\n',
        'ncpu=$(getconf _NPROCESSORS_ONLN)',
        'make -j $ncpu install',
        'make -j $ncpu rspamd-test',
        'make -j $ncpu rspamd-test-cxx',
      ],
    } + rspamd_volumes,
    {
      name: 'rspamd-test',
      image: 'rspamd/ci:ubuntu-test',
      pull: 'always',
      depends_on: [
        'build',
      ],
      commands: [
        'test "$(id -un)" = nobody',
        'ulimit -c unlimited',
        'cd /rspamd/build/test',
        'set +e',
        'env RSPAMD_LUA_EXPENSIVE_TESTS=1 ./rspamd-test -p /rspamd/lua; EXIT_CODE=$?',
        'set -e',
        "if [ $EXIT_CODE -gt 128 ]; then gdb --batch -ex 'thread apply all bt full' -c /var/tmp/*.rspamd-test.core ./rspamd-test; exit $EXIT_CODE; fi; if [ $EXIT_CODE -ne 0 ]; then exit $EXIT_CODE; fi\n",
        'luacov-coveralls -o /rspamd/build/unit_test_lua.json --dryrun',
        'set +e',
        './rspamd-test-cxx -s; EXIT_CODE=$?',
        'set -e',
        "if [ $EXIT_CODE -gt 128 ]; then gdb --batch -ex 'thread apply all bt full' -c /var/tmp/*.rspamd-test-cxx.core ./rspamd-test-cxx; exit $EXIT_CODE; fi\n",
        'exit $EXIT_CODE',
      ],
    } + rspamd_volumes,
    {
      name: 'test-fedora-clang',
      image: 'rspamd/ci:fedora-test',
      pull: 'always',
      depends_on: [
        'build-clang',
      ],
      commands: [
        'test "$(id -un)" = nobody',
        'ulimit -c 2097152',
        'ulimit -s unlimited',
        'export ASAN_OPTIONS="detect_leaks=0:print_stacktrace=1:disable_coredump=0"',
        'export UBSAN_OPTIONS="print_stacktrace=1:print_summary=0:log_path=/tmp/ubsan"',
        'cd /rspamd/fedora/build/test',
        'set +e',
        'env RSPAMD_LUA_EXPENSIVE_TESTS=1 ./rspamd-test -p /rspamd/lua; EXIT_CODE=$?',
        'set -e',
        "if [ $EXIT_CODE -gt 128 ]; then gdb --batch -ex 'bt' -c /var/tmp/*.rspamd-test.core ./rspamd-test; fi\n",
        'set +e',
        './rspamd-test-cxx -s; EXIT_CODE=$?',
        'set -e',
        "if [ $EXIT_CODE -gt 128 ]; then gdb --batch -ex 'thread apply all bt full' -c /var/tmp/*.rspamd-test-cxx.core ./rspamd-test-cxx; exit $EXIT_CODE; fi\n",
        'cat /tmp/ubsan.* || true',
        'exit $EXIT_CODE',
      ],
    } + rspamd_volumes,
    {
      name: 'functional',
      image: 'rspamd/ci:ubuntu-test-func',
      pull: 'always',
      depends_on: [
        'build',
      ],
      commands: [
        'cd /rspamd/build',
        'ulimit -c unlimited',
        'ulimit -s unlimited',
        'umask 0000',
        'set +e',
        'RSPAMD_INSTALLROOT=/rspamd/install robot --removekeywords wuks --exclude isbroken $DRONE_WORKSPACE/test/functional/cases; EXIT_CODE=$?',
        'set -e',
        'if [ -n "$HTTP_PUT_AUTH" ]; then $DRONE_WORKSPACE/test/tools/http_put.py log.html report.html https://$DRONE_SYSTEM_HOSTNAME/testlogs/$DRONE_REPO/$DRONE_BUILD_NUMBER/; fi\n',
        "core_files=$(find /var/tmp/ -name '*.core')",
        "for core in $core_files; do exe=$(gdb --batch -ex 'info proc mappings' -c $core | tail -1 | awk '{print $5}'); gdb --batch -ex 'bt' -c $core $exe; echo '---'; done\n",
        'exit $EXIT_CODE',
      ],
      environment: {
        HTTP_PUT_AUTH: {
          from_secret: 'http_put_auth',
        },
      },
    } + rspamd_volumes,
    {
      name: 'send-coverage',
      image: 'rspamd/ci:ubuntu-test',
      pull: 'if-not-exists',
      depends_on: [
        'functional',
        'rspamd-test',
      ],
      commands: [
        'cd /rspamd/build',
        '$DRONE_WORKSPACE/test/tools/gcov_coveralls.py --exclude test --prefix /rspamd/build --prefix $DRONE_WORKSPACE --out coverage.c.json',
        'luacov-coveralls -o coverage.functional.lua.json --dryrun',
        '$DRONE_WORKSPACE/test/tools/merge_coveralls.py --parallel --root $DRONE_WORKSPACE --input coverage.c.json unit_test_lua.json coverage.functional.lua.json --token=$COVERALLS_REPO_TOKEN',
      ],
      environment: {
        COVERALLS_REPO_TOKEN: {
          from_secret: 'coveralls_repo_token',
        },
      },
    } + coveralls_when + rspamd_volumes,
  ],
  volumes: [
    {
      name: 'rspamd',
      temp: {},
    },
  ],
} + platform(arch) + default_trigger + docker_pipeline;

local close_coveralls = {
  name: 'close_coveralls',
  depends_on: [
    'default-amd64',
    'default-arm64',
  ],
  steps: [
    {
      name: 'close_coveralls',
      image: 'rspamd/ci:ubuntu-test-func',
      pull: 'always',
      commands: [
        '$DRONE_WORKSPACE/test/tools/merge_coveralls.py --parallel-close --token=$COVERALLS_REPO_TOKEN',
      ],
      environment: {
        COVERALLS_REPO_TOKEN: {
          from_secret: 'coveralls_repo_token',
        },
      },
    },
  ],
} + coveralls_trigger + docker_pipeline;

local noarch_pipeline = {
  name: 'default-noarch',
  steps: [
    {
      name: 'perl-tidyall',
      image: 'rspamd/ci:perl-tidyall',
      pull: 'if-not-exists',
      failure: 'ignore',
      commands: [
        'tidyall --version',
        'perltidy --version | head -1',
        'tidyall --all --check-only --no-cache --data-dir /tmp/tidyall',
      ],
    },
    {
      name: 'eslint',
      image: 'node:18-alpine',
      pull: 'if-not-exists',
      failure: 'ignore',
      commands: [
        'npm install',
        './node_modules/.bin/eslint -v',
        './node_modules/.bin/eslint ./',
        './node_modules/.bin/stylelint -v',
        'npm show stylelint-config-standard version',
        './node_modules/.bin/stylelint ./**/*.css ./**/*.html ./**/*.js',
      ],
    },
  ],
} + default_trigger + docker_pipeline;

local signature = {
  kind: 'signature',
  hmac: '0000000000000000000000000000000000000000000000000000000000000000',
};

[
  pipeline('amd64'),
  pipeline('arm64'),
  close_coveralls,
  noarch_pipeline,
  notify_pipeline,
  signature,
]
