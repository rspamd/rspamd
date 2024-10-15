%if 0%{getenv:ASAN}
Name:             rspamd-asan
Conflicts:        rspamd
%else
Name:             rspamd
Conflicts:        rspamd-asan
%endif
Provides:         rspamd
Version:          3.2
Release:          1
Summary:          Rapid spam filtering system
Group:            System Environment/Daemons
License:          Apache-2.0
URL:              https://rspamd.com
Source0:          https://github.com/rspamd/rspamd/archive/%{version}/rspamd-%{version}.tar.gz
Source1:          rspamd.logrotate
Source2:          80-rspamd.preset
BuildRoot:        %{_tmppath}/%{name}-%{version}-%{release}
%if 0%{?el7}
BuildRequires:    cmake3
BuildRequires:    devtoolset-10-gcc-c++
%else
BuildRequires:    cmake
%if 0%{?el8}
BuildRequires:    gcc-toolset-10-gcc-c++
%endif
%if 0%{?el9}
BuildRequires:    gcc-toolset-12-gcc-c++
%endif
%endif
BuildRequires:    file-devel
BuildRequires:    glib2-devel
BuildRequires:    lapack-devel
BuildRequires:    libicu-devel
BuildRequires:    libsodium-devel
BuildRequires:    libunwind-devel
%if 0%{getenv:ASAN}
%if 0%{?el7}
BuildRequires:    devtoolset-10-libasan-devel
%else
%if 0%{?el8}
BuildRequires:    gcc-toolset-10-libasan-devel
%endif
%if 0%{?el9}
BuildRequires:    gcc-toolset-12-libasan-devel
%endif
%endif
%endif

%ifarch x86_64 amd64
%if 0%{?el8} || 0%{?fedora} > 10
BuildRequires:    hyperscan-devel
%endif
BuildRequires:    jemalloc-devel
%endif

%if 0%{getenv:LUAJIT}
BuildRequires:    git
%else
BuildRequires:    lua-devel
%endif
BuildRequires:    openblas-devel
BuildRequires:    openssl-devel
BuildRequires:    pcre2-devel
BuildRequires:    ragel
BuildRequires:    sqlite-devel
BuildRequires:    systemd
BuildRequires:    binutils-devel
Requires(pre):    shadow-utils
Requires(post):   systemd
Requires(preun):  systemd
Requires(postun): systemd

%description
Rspamd is a rapid, modular and lightweight spam filter. It is designed to work
with big amount of mail and can be easily extended with own filters written in
lua.

%prep
%setup -q -n %{name}-%{version}
%if 0%{getenv:LUAJIT}
rm -fr %{_builddir}/luajit-src || true
rm -fr %{_builddir}/luajit-build || true
git clone -b v2.1 https://luajit.org/git/luajit-2.0.git %{_builddir}/luajit-src
%endif

%build
%if 0%{?el7}
source /opt/rh/devtoolset-10/enable
%else
%if 0%{?el8}
source /opt/rh/gcc-toolset-10/enable
%endif
%if 0%{?el9}
source /opt/rh/gcc-toolset-12/enable
%endif
%endif

%if 0%{getenv:LUAJIT}
pushd %{_builddir}/luajit-src && make clean && make %{?_smp_mflags} CC="gcc -fPIC" PREFIX=%{_builddir}/luajit-build && make install PREFIX=%{_builddir}/luajit-build ; popd
rm -f %{_builddir}/luajit-build/lib/*.so || true
%endif
%if 0%{?el7}
%{cmake3} \
%else
%{cmake} \
%endif
	-B . \
%if 0%{getenv:ASAN}
        -DCMAKE_BUILD_TYPE=Debug \
        -DSANITIZE=address \
%else
        -DCMAKE_BUILD_TYPE=RelWithDebInfo \
        -DENABLE_LTO=ON \
%endif
        -DCMAKE_C_FLAGS_RELEASE="%{optflags}" \
        -DCMAKE_CXX_FLAGS_RELEASE="%{optflags}" \
%if 0%{?fedora} >= 36
        -DLINKER_NAME=/usr/bin/ld.bfd \
%endif
%if 0%{?el8}
        -DLINKER_NAME=ld.bfd \
%endif
        -DCMAKE_INSTALL_PREFIX=%{_prefix} \
        -DCONFDIR=%{_sysconfdir}/rspamd \
        -DMANDIR=%{_mandir} \
        -DDBDIR=%{_localstatedir}/lib/rspamd \
        -DRUNDIR=%{_localstatedir}/run/rspamd \
        -DLOGDIR=%{_localstatedir}/log/rspamd \
        -DEXAMPLESDIR=%{_datadir}/examples/rspamd \
        -DSHAREDIR=%{_datadir}/rspamd \
        -DLIBDIR=%{_libdir}/rspamd/ \
        -DINCLUDEDIR=%{_includedir} \
        -DRSPAMD_GROUP=_rspamd \
        -DRSPAMD_USER=_rspamd \
        -DSYSTEMDDIR=%{_unitdir} \
        -DWANT_SYSTEMD_UNITS=ON \
        -DNO_SHARED=ON \
        -DNO_TARGET_VERSIONS=1 \
%ifarch x86_64 amd64 arm64 aarch64
        -DENABLE_HYPERSCAN=ON \
%endif
%ifarch arm64 aarch64
        -DHYPERSCAN_ROOT_DIR=/vectorscan \
%endif
%ifarch x86_64 amd64
%if 0%{?el7}
        -DHYPERSCAN_ROOT_DIR=/vectorscan \
%endif
%endif
%ifarch x86_64 amd64
        -DENABLE_JEMALLOC=ON \
%endif
%if 0%{getenv:LUAJIT}
        -DENABLE_LUAJIT=ON \
	      -DLUA_ROOT=%{_builddir}/luajit-build \
%else
        -DENABLE_LUAJIT=OFF \
%endif
        -DENABLE_FASTTEXT=ON \
        -DFASTTEXT_ROOT_DIR=/fasttext \
        -DENABLE_BLAS=ON
make %{?_smp_mflags}

%install
%make_install
%{__install} -p -D -m 0644 %{SOURCE1} %{buildroot}%{_sysconfdir}/logrotate.d/rspamd
%{__install} -p -D -m 0644 %{SOURCE2} %{buildroot}%{_presetdir}/80-rspamd.preset
%{__install} -d -p -m 0755 %{buildroot}%{_localstatedir}/log/rspamd
%{__install} -d -p -m 0755 %{buildroot}%{_localstatedir}/lib/rspamd
%{__install} -p -D -d -m 0755 %{buildroot}%{_sysconfdir}/rspamd/local.d/
%{__install} -p -D -d -m 0755 %{buildroot}%{_sysconfdir}/rspamd/override.d/

%clean
rm -rf %{buildroot}

%pre
%{_sbindir}/groupadd -r _rspamd 2>/dev/null || :
%{_sbindir}/useradd -g _rspamd -c "Rspamd user" -s /bin/false -r -d %{_localstatedir}/lib/rspamd _rspamd 2>/dev/null || :

%post
%{__chown} -R _rspamd:_rspamd %{_localstatedir}/lib/rspamd
%{__chown} _rspamd:_rspamd %{_localstatedir}/log/rspamd
%if 0%{?el7}
# We need to clean old hyperscan files on upgrade: see https://github.com/rspamd/rspamd/issues/4441
rm -f %{_localstatedir}/lib/rspamd/*.hs*
%endif
systemctl --no-reload preset rspamd.service >/dev/null 2>&1 || :

%preun
%systemd_preun rspamd.service

%postun
%systemd_postun_with_restart rspamd.service

%files
%defattr(-,root,root,-)

%dir %{_sysconfdir}/rspamd
%config(noreplace) %{_sysconfdir}/rspamd/*

%{_bindir}/rspamd
%{_bindir}/rspamd_stats
%{_bindir}/rspamc
%{_bindir}/rspamadm

%{_unitdir}/rspamd.service
%{_presetdir}/80-rspamd.preset

%dir %{_libdir}/rspamd
%{_libdir}/rspamd/*

%{_mandir}/man8/rspamd.*
%{_mandir}/man1/rspamc.*
%{_mandir}/man1/rspamadm.*

%dir %{_datadir}/rspamd
%{_datadir}/rspamd/*

%config(noreplace) %{_sysconfdir}/logrotate.d/rspamd

%attr(-, _rspamd, _rspamd) %dir %{_localstatedir}/lib/rspamd
%dir %{_localstatedir}/log/rspamd
