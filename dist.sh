#!/bin/sh

ver=`cat ibsim/ibsim.c | sed -ne '/#define IBSIM_VERSION /s/^#define IBSIM_VERSION \"\(.*\)\"/\1/p'`
rel=1
distdir=ibsim-${ver}
tarball=${distdir}.tar.gz

test -z "$RELEASE" || rel=$RELEASE

dch_entry() {
	cat <<EOF
ibsim ($ver) unstable; urgency=low

  * New upstream release.

 --  Tzafrir Cohen <nvidia@cohens.org.il>  `date -R`

EOF
}

rm -f $tarball
rm -rf $distdir
mkdir $distdir

files=`find . -name '*.[ch]' -o -name Makefile -o -name '*.in'`
cp -a --parents $files debian \
	defs.mk README COPYING TODO net-examples scripts tests $distdir

cat ibsim.spec.in \
		| sed -e 's/@VERSION@/'$ver'/' -e 's/@RELEASE@/'$rel'/' -e 's/@TARBALL@/'$tarball'/' \
		> $distdir/ibsim.spec

(dch_entry; cat debian/changelog) >$distdir/debian/changelog

tar czf $tarball $distdir
rm -rf $distdir
