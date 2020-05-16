bins:=ibsim
scripts:=ibsim-run
progs:=$(bins) $(scrips)

-include ../defs.mk

ibsim-run: ibsim-run.in
	sed -e 's|@sim_so@|$(libdir)/libumad2sim.so|' \
		<$< >$@
	chmod +x $@

all: $(progs)
ibsim: $(objs)
