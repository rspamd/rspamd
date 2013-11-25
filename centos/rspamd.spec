%define rspamd_user      rspamd
%define rspamd_group     %{rspamd_user}
%define rspamd_home      %{_localstatedir}/lib/rspamd
%define rspamd_logdir    %{_localstatedir}/log/rspamd
%define rspamd_confdir   %{_sysconfdir}/rspamd
%define rspamd_pluginsdir   %{_datadir}/rspamd

%define USE_JUDY         0

Name:           rspamd
Version:        0.6.0
Release:        1
Summary:        Rapid spam filtering system
Group:          System Environment/Daemons   

# BSD License (two clause)
# http://www.freebsd.org/copyright/freebsd-license.html
License:        BSD
URL:            https://bitbucket.org/vstakhov/rspamd/ 
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}
%if USE_JUDY
BuildRequires:  cmake,glib2-devel,gmime-devel,libevent-devel,openssl-devel,lua-devel,Judy-devel
Requires:       glib2,gmime,lua,Judy,libevent
%else
BuildRequires:  cmake,glib2-devel,gmime-devel,libevent-devel,openssl-devel,lua-devel
Requires:       glib2,gmime,lua,libevent
%endif
# for /user/sbin/useradd
Requires(pre):  shadow-utils
Requires(post): chkconfig
# for /sbin/service
Requires(preun):        chkconfig, initscripts
Requires(postun):       initscripts

Source0:        http://cdn.bitbucket.org/vstakhov/rspamd/downloads/%{name}-%{version}.tar.gz
Source1:        %{name}.init
Source2:        %{name}.logrotate

%description
Rspamd is a rapid, modular and lightweight spam filter. It is designed to work
with big amount of mail and can be easily extended with own filters written in
lua.

%prep
%setup -q

%build
rm -rf %{buildroot}
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
%if USE_JUDY
        -DENABLE_JUDY=ON
%else
        -DENABLE_JUDY=OFF
%endif

%{__make} %{?jobs:-j%jobs}

%install
%{__make} install DESTDIR=%{buildroot} INSTALLDIRS=vendor

%{__install} -p -D -m 0755 %{SOURCE1} %{buildroot}%{_initrddir}/%{name}
%{__install} -p -D -m 0644 %{SOURCE2} %{buildroot}%{_sysconfdir}/logrotate.d/%{name}
%{__install} -p -D -m 0644 %{SOURCE3} %{buildroot}%{_sysconfdir}/%{name}.xml
%{__install} -d -p -m 0755 %{buildroot}%{rspamd_logdir}
%{__install} -o %{rspamd_user} -g %{rspamd_group} -d -p -m 0755 %{buildroot}%{rspamd_home}

%clean
rm -rf %{buildroot}

%pre
%{_sbindir}/useradd -c "Rspamd user" -s /bin/false -r -d %{rspamd_home} %{rspamd_user} 2>/dev/null || :

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

%files
%defattr(-,root,root,-)
%{_initrddir}/%{name}
%{_mandir}/man8/%{name}.*
%{_mandir}/man1/rspamc.*
%{_bindir}/rspamd
%{_bindir}/rspamc
%config(noreplace) %{rspamd_confdir}/%{name}.conf
%config(noreplace) %{_sysconfdir}/logrotate.d/%{name}
%dir %{rspamd_logdir}
%dir %{rspamd_confdir}
%attr(755, %{rspamd_user}, %{rspamd_group}) %dir %{rspamd_home}
%config(noreplace) %{rspamd_confdir}/2tld.inc
%config(noreplace) %{rspamd_confdir}/surbl-whitelist.inc
%config(noreplace) %{rspamd_pluginsdir}/lua/forged_recipients.lua
%config(noreplace) %{rspamd_pluginsdir}/lua/maillist.lua
%config(noreplace) %{rspamd_pluginsdir}/lua/multimap.lua
%config(noreplace) %{rspamd_pluginsdir}/lua/once_received.lua
%config(noreplace) %{rspamd_pluginsdir}/lua/rbl.lua
%config(noreplace) %{rspamd_pluginsdir}/lua/ratelimit.lua
%config(noreplace) %{rspamd_pluginsdir}/lua/whitelist.lua
%config(noreplace) %{rspamd_pluginsdir}/lua/phishing.lua
%config(noreplace) %{rspamd_pluginsdir}/lua/trie.lua
%config(noreplace) %{rspamd_pluginsdir}/lua/emails.lua
%config(noreplace) %{rspamd_pluginsdir}/lua/ip_score.lua
%config(noreplace) %{rspamd_confdir}/lua/regexp/drugs.lua
%config(noreplace) %{rspamd_confdir}/lua/regexp/fraud.lua
%config(noreplace) %{rspamd_confdir}/lua/regexp/headers.lua
%config(noreplace) %{rspamd_confdir}/lua/regexp/lotto.lua
%config(noreplace) %{rspamd_confdir}/lua/rspamd.lua
%config(noreplace) %{rspamd_confdir}/lua/rspamd.classifiers.lua

%changelog
* Tue Nov 19 2013 Vsevolod Stakhov <vsevolod-at-highsecure.ru> 0.6.0-1
- Update to 0.6.0.

* Mon Jun 10 2013 Vsevolod Stakhov <vsevolod-at-highsecure.ru> 0.5.6-1
- Update to 0.5.6.

* Sat May 25 2013 Vsevolod Stakhov <vsevolod-at-highsecure.ru> 0.5.5-1
- Initial spec version.
