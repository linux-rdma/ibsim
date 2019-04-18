subdirs:= ibsim umad2sim tests

all clean dep install:
	$(foreach dir, $(subdirs), make -C $(dir) $@ && ) echo "Done."

dist:
	./dist.sh RELEASE=$(RELEASE)
