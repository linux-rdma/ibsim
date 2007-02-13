#!/bin/sh

if [ "$1" = "-g" ] ; then
	debug=1
	shift
fi

if [ -z "$1" ] ; then
	cmd=opensm
	cmd_args="-e -c -V -f ./osm.log -s 0"
else
	cmd="$1"
	shift
	cmd_args="$*"
fi

# for example to run OpenSM from Hca1 node of net.2sw2path
#SIM_HOST="Hca1"

OSM_TMP_DIR=./
OSM_CACHE_DIR=./

umad2sim=`dirname $0`/../umad2sim/libumad2sim.so


rm -f ${OSM_CACHE_DIR}/.guid2lid

if [ -z "$debug" ] ; then
	export SIM_HOST
	export OSM_TMP_DIR
	export OSM_CACHE_DIR
	time LD_PRELOAD=${umad2sim} ${cmd} ${cmd_args}
	rc=$?
	exit $rc
else
	test -f .gdbinit && mv .gdbinit gdbinit-saved
	echo > .gdbinit
	echo set environment SIM_HOST ${SIM_HOST} >> .gdbinit
	echo set environment OSM_TMP_DIR ${OSM_TMP_DIR} >> .gdbinit
	echo set environment OSM_CACHE_DIR ${OSM_CACHE_DIR} >> .gdbinit
	echo set environment LD_PRELOAD ${umad2sim} >> .gdbinit
	echo handle SIGHUP noprint nostop pass >> .gdbinit
	echo handle SIGTERM print stop pass >> .gdbinit
	#echo break sim_client_init >> .gdbinit
	echo break main >> .gdbinit
	echo run ${cmd_args} >> .gdbinit
	gdb ${cmd}
fi
