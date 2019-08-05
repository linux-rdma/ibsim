subdirs:= ibsim umad2sim
subdirs_with_tests:=$(subdirs) tests

all clean dep:
	$(foreach dir, $(subdirs_with_tests), make -C $(dir) $@ && ) echo "Done."

install:
	$(foreach dir, $(subdirs), make -C $(dir) $@ && ) echo "Done."

dist:
	./dist.sh RELEASE=$(RELEASE)
