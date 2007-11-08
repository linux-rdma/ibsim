subdirs:= ibsim umad2sim

all clean dep install:
	$(foreach dir, $(subdirs), make -C $(dir) $@ && ) echo "Done."

dist:
	./dist.sh RELEASE=$(RELEASE)
