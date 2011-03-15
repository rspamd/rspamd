#!/bin/sh
# Makes manual pages from pods

POD2MAN="pod2man"
VERSION="unknown"
CMAKEFILE="../CMakeLists.txt"

# Extract release version
if [ -f ${CMAKEFILE} ] ; then
	_mjver=`fgrep 'SET(RSPAMD_VERSION_MAJOR' ${CMAKEFILE} | sed -e 's/^.*RSPAMD_VERSION_MAJOR \([0-9]\).*/\1/'`
	_miver=`fgrep 'SET(RSPAMD_VERSION_MINOR' ${CMAKEFILE} | sed -e 's/^.*RSPAMD_VERSION_MINOR \([0-9]\).*/\1/'`
	_pver=`fgrep 'SET(RSPAMD_VERSION_PATCH' ${CMAKEFILE} | sed -e 's/^.*RSPAMD_VERSION_PATCH \([0-9]\).*/\1/'`
	VERSION="${_mjver}.${_miver}.${_pver}"
fi

pod2man -c "Rspamd documentation" -n rspamd -s 8 -r "rspamd-${VERSION}" < rspamd.pod > rspamd.8
pod2man -c "Rspamd documentation" -n rspamc -s 1 -r "rspamd-${VERSION}" < rspamc.pod > rspamc.1
