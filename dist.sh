#!/bin/sh

TAR=${2:-"tar"}

if [ $# -lt 1 ] ; then
	echo "Usage: dist.sh <filename> [tar_command]"
	exit 1
fi

FNAME=$1
PREFIX=`basename $FNAME | sed -e 's/\.tar.*$//'`

OUT=""
while true ; do
	OUT="/tmp/files-`strings -7 /dev/urandom | head -1 | sed -e 's/[^[:alnum:]]//g'`"
	if [ ! -f "$OUT" ] ; then break ; fi
done

git ls-files > $OUT
SUBMODULES=`git submodule | cut -d ' ' -f 3`

for sub in $SUBMODULES ; do
	(cd $sub && git ls-files | sed -e "s|^|$sub/|" >> $OUT)
done

${TAR} -c --exclude='.[^/]*' --exclude='*.xz' --exclude='*.gz' --no-recursion --transform "s|^|$PREFIX/|" -a -T $OUT -v -f $FNAME
rm -f $OUT
