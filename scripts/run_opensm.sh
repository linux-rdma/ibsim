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

# setup valid libumad2sim.so path here
# when installed it can be $(libdir)/lib/umad2sim/libumad2sim.so
umad2sim=`dirname $0`/../umad2sim/libumad2sim.so


if [ -z "$debug" ] ; then
	export SIM_HOST
	export OSM_TMP_DIR
	export OSM_CACHE_DIR
	time LD_PRELOAD=${umad2sim} ${cmd} ${cmd_args}
	rc=$?
	exit $rc
else
	cmd_file=ibsim-gdb-init
	test -f ${cmd_file} && mv ${cmd_file} ${cmd_file}-saved
	echo > ${cmd_file}
	echo set environment SIM_HOST ${SIM_HOST} >> ${cmd_file}
	echo set environment OSM_TMP_DIR ${OSM_TMP_DIR} >> ${cmd_file}
	echo set environment OSM_CACHE_DIR ${OSM_CACHE_DIR} >> ${cmd_file}
	echo set environment LD_PRELOAD ${umad2sim} >> ${cmd_file}
	echo handle SIGHUP noprint nostop pass >> ${cmd_file}
	echo handle SIGUSR1 noprint nostop pass >> ${cmd_file}
	echo handle SIGTERM print stop pass >> ${cmd_file}
	#echo break sim_client_init >> ${cmd_file}
	echo break main >> ${cmd_file}
	echo run ${cmd_args} >> ${cmd_file}
	gdb --command=${cmd_file} ${cmd}
fi
