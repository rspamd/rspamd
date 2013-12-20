%define rspamd_user      rspamd
%define rspamd_group     %{rspamd_user}
%define rspamd_home      %{_localstatedir}/lib/rspamd
%define rspamd_logdir    %{_localstatedir}/log/rspamd
%define rspamd_confdir   %{_sysconfdir}/rspamd
%define rspamd_pluginsdir   %{_datadir}/rspamd

%define USE_JUDY         0

%if 0%{?suse_version}
%define __cmake cmake
%define __install install
%define __make make
%define __chown chown
%endif

Name:           rspamd
Version:        0.6.4
Release:        1
Summary:        Rapid spam filtering system
Group:          System Environment/Daemons   

# BSD License (two clause)
# http://www.freebsd.org/copyright/freebsd-license.html
License:        BSD2c
URL:            https://rspamd.com
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}
%if "%{USE_JUDY}" == "1"
BuildRequires:  cmake,glib2-devel,gmime-devel,libevent-devel,openssl-devel,lua-devel,Judy-devel,pcre-devel
Requires:       lua, logrotate
%else
BuildRequires:  cmake,glib2-devel,gmime-devel,libevent-devel,openssl-devel,lua-devel,pcre-devel
Requires:       lua, logrotate
%endif
# for /user/sbin/useradd
%if 0%{?suse_version}
Requires(pre):  shadow, %insserv_prereq, %fillup_prereq
%else
Requires(pre):  shadow-utils
Requires(post): chkconfig
# for /sbin/service
Requires(preun):        chkconfig, initscripts
Requires(postun):       initscripts
%endif

Source0:        https://rspamd.com/downloads/%{name}-%{version}.tar.gz
Source1:        %{name}.init
Source2:        %{name}.logrotate

%description
Rspamd is a rapid, modular and lightweight spam filter. It is designed to work
with big amount of mail and can be easily extended with own filters written in
lua.

%prep
%setup -q

%build
%{__cmake} \
        -DCMAKE_INSTALL_PREFIX=%{_prefix} \
        -DCONFDIR=%{_sysconfdir}/rspamd \
        -DMANDIR=%{_mandir} \
        -DDBDIR=%{_localstatedir}/lib/rspamd \
        -DRUNDIR=%{_localstatedir}/run/rspamd \
        -DLOGDIR=%{_localstatedir}/log/rspamd \
        -DEXAMPLESDIR=%{_datadir}/examples/rspamd \
        -DPLUGINSDIR=%{_datadir}/rspamd \
        -DLIBDIR=%{_libdir} \
        -DINCLUDEDIR=%{_includedir} \
        -DNO_SHARED=ON \
        -DDEBIAN_BUILD=1 \
        -DRSPAMD_GROUP=%{rspamd_group} \
        -DRSPAMD_USER=%{rspamd_user} \
%if "%{USE_JUDY}" == "1"
        -DENABLE_JUDY=ON
%else
        -DENABLE_JUDY=OFF
%endif

%{__make} %{?jobs:-j%jobs}

%install
%{__make} install DESTDIR=%{buildroot} INSTALLDIRS=vendor

%{__install} -p -D -m 0755 %{SOURCE1} %{buildroot}%{_initrddir}/%{name}

%if 0%{?suse_version}
mkdir -p %{buildroot}%{_sbindir}
ln -sf %{_initrddir}/rspamd %{buildroot}%{_sbindir}/rcrspamd
%endif

%{__install} -p -D -m 0644 %{SOURCE2} %{buildroot}%{_sysconfdir}/logrotate.d/%{name}
%{__install} -d -p -m 0755 %{buildroot}%{rspamd_logdir}
%{__install} -d -p -m 0755 %{buildroot}%{rspamd_home}

%clean
rm -rf %{buildroot}

%pre
%{_sbindir}/groupadd -r %{rspamd_group} 2>/dev/null || :
%{_sbindir}/useradd -g %{rspamd_group} -c "Rspamd user" -s /bin/false -r -d %{rspamd_home} %{rspamd_user} 2>/dev/null || :

%if 0%{?suse_version}

%post
%fillup_and_insserv rspamd

%preun
%stop_on_removal rspamd

%postun
%restart_on_update rspamd
%insserv_cleanup

%else

%post
/sbin/chkconfig --add %{name}

%preun
if [ $1 = 0 ]; then
    /sbin/service %{name} stop >/dev/null 2>&1
    /sbin/chkconfig --del %{name}
fi

%postun
if [ $1 -ge 1 ]; then
    /sbin/service %{name} condrestart > /dev/null 2>&1 || :
fi

%endif

%files
%defattr(-,root,root,-)
%{_initrddir}/%{name}
%{_mandir}/man8/%{name}.*
%{_mandir}/man1/rspamc.*
%{_bindir}/rspamd
%{_bindir}/rspamc
%config(noreplace) %{rspamd_confdir}/%{name}.conf
%config(noreplace) %{rspamd_confdir}/composites.conf
%config(noreplace) %{rspamd_confdir}/logging.conf
%config(noreplace) %{rspamd_confdir}/metrics.conf
%config(noreplace) %{rspamd_confdir}/modules.conf
%config(noreplace) %{rspamd_confdir}/options.conf
%config(noreplace) %{rspamd_confdir}/statistic.conf
%config(noreplace) %{rspamd_confdir}/workers.conf
%config(noreplace) %{_sysconfdir}/logrotate.d/%{name}
%dir %{rspamd_logdir}
%dir %{rspamd_home}
%dir %{rspamd_confdir}/lua/regexp
%dir %{rspamd_confdir}/lua
%dir %{rspamd_confdir}
%dir %{rspamd_pluginsdir}/lua
%dir %{rspamd_pluginsdir}
%config(noreplace) %{rspamd_confdir}/2tld.inc
%config(noreplace) %{rspamd_confdir}/surbl-whitelist.inc
%{rspamd_pluginsdir}/lua/forged_recipients.lua
%{rspamd_pluginsdir}/lua/maillist.lua
%{rspamd_pluginsdir}/lua/multimap.lua
%{rspamd_pluginsdir}/lua/once_received.lua
%{rspamd_pluginsdir}/lua/rbl.lua
%{rspamd_pluginsdir}/lua/ratelimit.lua
%{rspamd_pluginsdir}/lua/whitelist.lua
%{rspamd_pluginsdir}/lua/phishing.lua
%{rspamd_pluginsdir}/lua/trie.lua
%{rspamd_pluginsdir}/lua/emails.lua
%{rspamd_pluginsdir}/lua/ip_score.lua
%config(noreplace) %{rspamd_confdir}/lua/regexp/drugs.lua
%config(noreplace) %{rspamd_confdir}/lua/regexp/fraud.lua
%config(noreplace) %{rspamd_confdir}/lua/regexp/headers.lua
%config(noreplace) %{rspamd_confdir}/lua/regexp/lotto.lua
%config(noreplace) %{rspamd_confdir}/lua/rspamd.lua
%config(noreplace) %{rspamd_confdir}/lua/rspamd.classifiers.lua
%if 0%{?suse_version}
%{_sbindir}/rcrspamd
%endif

%changelog
* Wed Dec 18 2013 Vsevolod Stakhov <vsevolod-at-highsecure.ru> 0.6.4-1
- Update to 0.6.4.

* Tue Dec 10 2013 Vsevolod Stakhov <vsevolod-at-highsecure.ru> 0.6.3-1
- Update to 0.6.3.

* Tue Dec 06 2013 Vsevolod Stakhov <vsevolod-at-highsecure.ru> 0.6.2-1
- Update to 0.6.2.

* Tue Nov 19 2013 Vsevolod Stakhov <vsevolod-at-highsecure.ru> 0.6.0-1
- Update to 0.6.0.

* Mon Jun 10 2013 Vsevolod Stakhov <vsevolod-at-highsecure.ru> 0.5.6-1
- Update to 0.5.6.

* Sat May 25 2013 Vsevolod Stakhov <vsevolod-at-highsecure.ru> 0.5.5-1
- Initial spec version.
