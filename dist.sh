#!/bin/sh

ver=`cat ibsim/ibsim.c | sed -ne '/#define IBSIM_VERSION /s/^#define IBSIM_VERSION \"\(.*\)\"/\1/p'`
rel=1
distdir=ibsim-${ver}
tarball=${distdir}.tar.gz

test -z "$RELEASE" || rel=$RELEASE

rm -f $tarball
rm -rf $distdir
mkdir $distdir

files=`find . -name '*.[ch]' -o -name Makefile`
cp -a --parents $files \
	defs.mk README COPYING TODO net-examples scripts tests $distdir

cat ibsim.spec.in \
		| sed -e 's/@VERSION@/'$ver'/' -e 's/@RELEASE@/'$rel'/' -e 's/@TARBALL@/'$tarball'/' \
		> $distdir/ibsim.spec

tar czf $tarball $distdir
rm -rf $distdir
