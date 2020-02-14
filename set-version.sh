#!/bin/bash
# Update the version after a new release.
version=$1
if ! [[ "$version" =~ ^[0-9]+.[0-9]+$ ]]; then
    echo "Usage: $0 <major>.<minor>"
    exit 1
fi

read major minor <<< "${version/./ }"
sed -e "s/^\\(SET(RSPAMD_VERSION_MAJOR \\)[0-9]*)/\\1$major)/" \
    -e "s/^\\(SET(RSPAMD_VERSION_MINOR \\)[0-9]*)/\\1$minor)/" \
    -i CMakeLists.txt
sed -e "1s/([0-9.]*)/($version)/" -i debian/changelog
sed -e "s/^\\(Version: *\\)[0-9.]*$/\\1$version/" -i centos/rspamd.spec
