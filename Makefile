subdirs:= ibsim umad2sim

all clean dep:
	$(foreach dir, $(subdirs), make -C $(dir) $@ && ) echo "Done."
