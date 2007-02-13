
#IB_DEV_DIR:=$(HOME)/src/p
ifdef IB_DEV_DIR
 INCS:= $(foreach l, mad umad common, -I$(IB_DEV_DIR)/libib$(l)/include) \
  -I/usr/local/include
 LIBS:= \
  $(foreach l, mad umad common, $(IB_DEV_DIR)/libib$(l)/.libs/libib$(l).so)
else
 INCS:= -I/usr/local/include
 LIBS:= -L/usr/local/lib -libmad -libumad -libcommon
endif

CFLAGS:= -Wall -g -fpic -I. -I../include $(INCS)
LDFLAGS:= -fpic

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

$(objs): .build_profile
.build_profile::
	@echo CFLAGS=$(CFLAGS) > .build_profile.new
	@if ( test -f .build_profile \
	   && diff .build_profile .build_profile.new > /dev/null ) ; then \
		rm .build_profile.new ; \
	else mv .build_profile.new .build_profile ; fi
