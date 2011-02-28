
old_ofed:=/usr/local/ofed

prefix:= $(strip $(if $(prefix),$(prefix),\
	$(if $(wildcard $(old_ofed)/lib64/libibumad.so \
		$(old_ofed)/lib/libibumad.so),$(old_ofed),\
	$(if $(wildcard /usr/local/lib/libibumad.so \
		/usr/local/lib64/libibumad.so),/usr/local,\
	$(if $(wildcard /usr/lib /usr/lib64),/usr,/tmp/unknown)))))

libpath:= $(strip $(if $(libpath),$(libpath),\
	$(if $(wildcard $(prefix)/lib64/libibumad.so),\
		$(prefix)/lib64,$(prefix)/lib)))
binpath:= $(if $(binpath),$(binpath),$(prefix)/bin)

#IB_DEV_DIR:=$(HOME)/src/m
ifdef IB_DEV_DIR
 INCS:= $(foreach l, mad umad, -I$(IB_DEV_DIR)/libib$(l)/include) \
  -I/usr/local/include
 LIBS:= \
  $(foreach l, mad umad, $(IB_DEV_DIR)/libib$(l)/.libs/libib$(l).so)
else
 INCS:= -I$(dir $(libpath))include
 LIBS:= -L$(libpath) -libmad -libumad
endif

CFLAGS += -Wall -g -fpic -I. -I../include $(INCS)
LDFLAGS+= -fpic

srcs?=$(wildcard *.c)
objs?=$(srcs:.c=.o)

.PHONY: all clean dep install

all:

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

%.so:
	$(CC) -shared $(LDFLAGS) -o $@ $^ $(LIBS)

$(progs):
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

dep:
	$(CC) -M $(CFLAGS) $(srcs) > .depend
-include .depend

clean:
	$(RM) $(objs) $(libs) $(progs)
	$(RM) .build_profile
	$(RM) *.o *.a *.so *~

install: all
	install -d $(DESTDIR)$(binpath)
	install -d $(DESTDIR)$(libpath)/umad2sim
	$(foreach p, $(progs), install $(p) $(DESTDIR)$(binpath))
	$(foreach l, $(libs), install $(l) $(DESTDIR)$(libpath)/umad2sim)

$(objs): .build_profile
.build_profile::
	@echo CFLAGS=$(CFLAGS) > .build_profile.new
	@if ( test -f .build_profile \
	   && diff .build_profile .build_profile.new > /dev/null ) ; then \
		rm .build_profile.new ; \
	else mv .build_profile.new .build_profile ; fi
