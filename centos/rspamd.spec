%define rspamd_user      rspamd
%define rspamd_group     %{rspamd_user}
%define rspamd_home      %{_localstatedir}/lib/rspamd
%define rspamd_logdir    %{_localstatedir}/log/rspamd
%define rspamd_confdir   %{_sysconfdir}/rspamd

Name:           rspamd
Version:        0.5.5
Release:        1
Summary:        Rapid spam filtering system
Group:          System Environment/Daemons   

# BSD License (two clause)
# http://www.freebsd.org/copyright/freebsd-license.html
License:        BSD
URL:            https://bitbucket.org/vstakhov/rspamd/ 
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}
BuildRequires:  cmake,glib2-devel,gmime-devel,openssl-devel,lua-devel,Judy-devel
Requires:       glib2,gmime,lua,Judy
# for /user/sbin/useradd
Requires(pre):  shadow-utils
Requires(post): chkconfig
# for /sbin/service
Requires(preun):        chkconfig, initscripts
Requires(postun):       initscripts

Source0:        http://cdn.bitbucket.org/vstakhov/rspamd/downloads/%{name}-%{version}.tar.gz
Source1:        %{name}.init
Source2:        %{name}.logrotate
Source3:        %{name}.xml

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
        -DETC_PREFIX=%{_sysconfdir} \
        -DMAN_PREFIX=%{_mandir} \
        -DLOCALSTATES_PREFIX=%{_localstatedir}/lib \
        -DLIBDIR=%{_libdir} \
        -DINCLUDEDIR=%{_includedir} \
        -DNO_SHARED=ON \
        -DDEBIAN_BUILD=1 \
        -DRSPAMD_GROUP=%{rspamd_group} \
        -DRSPAMD_USER=%{rspamd_user}

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
%config(noreplace) %{_sysconfdir}/%{name}.xml
%config(noreplace) %{_sysconfdir}/logrotate.d/%{name}
%dir %{rspamd_logdir}
%dir %{rspamd_confdir}
%attr(755, %{rspamd_user}, %{rspamd_group}) %dir %{rspamd_home}
%config(noreplace) %{rspamd_confdir}/2tld.inc
%config(noreplace) %{rspamd_confdir}/surbl-whitelist.inc
%config(noreplace) %{rspamd_confdir}/plugins/lua/forged_recipients.lua
%config(noreplace) %{rspamd_confdir}/plugins/lua/maillist.lua
%config(noreplace) %{rspamd_confdir}/plugins/lua/multimap.lua
%config(noreplace) %{rspamd_confdir}/plugins/lua/once_received.lua
%config(noreplace) %{rspamd_confdir}/plugins/lua/received_rbl.lua
%config(noreplace) %{rspamd_confdir}/plugins/lua/ratelimit.lua
%config(noreplace) %{rspamd_confdir}/plugins/lua/whitelist.lua
%config(noreplace) %{rspamd_confdir}/plugins/lua/phishing.lua
%config(noreplace) %{rspamd_confdir}/plugins/lua/trie.lua
%config(noreplace) %{rspamd_confdir}/plugins/lua/emails.lua
%config(noreplace) %{rspamd_confdir}/plugins/lua/ip_score.lua
%config(noreplace) %{rspamd_confdir}/lua/regexp/drugs.lua
%config(noreplace) %{rspamd_confdir}/lua/regexp/fraud.lua
%config(noreplace) %{rspamd_confdir}/lua/regexp/headers.lua
%config(noreplace) %{rspamd_confdir}/lua/regexp/lotto.lua
%config(noreplace) %{rspamd_confdir}/lua/rspamd.lua
%config(noreplace) %{rspamd_confdir}/lua/rspamd.classifiers.lua

%changelog
* Sat May 25 2013 Vsevolod Stakhov <vsevolod-at-highsecure.ru> 0.5.5-1
- Initial spec version.
