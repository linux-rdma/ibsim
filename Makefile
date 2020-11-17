subdirs:= ibsim umad2sim
subdirs_with_tests:=$(subdirs) tests

all clean dep:
	$(foreach dir, $(subdirs_with_tests), make -C $(dir) $@ && ) echo "Done."

install:
	$(foreach dir, $(subdirs), make -C $(dir) $@ && ) echo "Done."

dist:
	./dist.sh RELEASE=$(RELEASE)

distcheck: dist
	@set -e; set -x; \
	tarball=`ls -t *.tar.gz | head -n 1`; \
	rm -rf checkdir; \
	mkdir checkdir; \
	cd checkdir; \
	tar xzf ../$$tarball; \
	cd *; \
	make; \
	make install DESTDIR=`pwd`/root; \
	cd .. ;\
	rm -rf checkdir

.PHONEY: all clean dep dist distcheck install
