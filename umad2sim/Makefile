srcs:=umad2sim.c sim_client.c
objs:=$(srcs:.c=.o)
libs:=libumad2sim.so

-include ../defs.mk

#CFLAGS+= -DUMAD2SIM_NOISY_DEBUG
#CFLAGS+= -DSIM_CLIENT_NOISY_DEBUG
LIBS+= -ldl
$(libs): $(objs)
all: $(libs)
