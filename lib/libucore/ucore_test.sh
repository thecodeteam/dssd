#!/bin/bash -p

#
# Copyright 2017 Dell Inc. or its subsidiaries.  All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# 

#
# libucore test
#
# There is a massive amount of verification that could be done here, but for
# the moment we cover the basic sanity checking in an automated fashion:
#
# 1. verify that we get a user core and it is valid ELF
# 2. verify that we get a kernel core and it is valid ELF
# 3. verify that we preserve the exit status as WIFSIGNALED and WTERMSIG
# 4. verify that we have the same list of PT_LOAD Phdrs in both core files
# 5. verify that gdb sees the same basic prstatus, stack, and registers
#
# The other stuff that must be hand-verified at the moment includes:
#
# 6. PT_LOAD binary content (other than referenced by 5 above)
# 7. PT_NOTE binary content (other than referenced by 5 above)
# 8. Shdr content for ucore
#

export PATH=/bin:/usr/bin
shopt -s xpg_echo

export UCORE_PATH=ucore.%p
export UCORE_OPTIONS=user,kernel,banner

wstat=$?
errs=0

function fatal
{
	echo "FAIL: $*" >& 2
	errs=$(($errs + 1))
	exit $errs
}

function fail
{
	echo "FAIL: $*" >& 2
	errs=$(($errs + 1))
	return 1
}

if [[ $(</proc/sys/kernel/core_pattern) != core.%p ]]; then
	echo "$0: /proc/sys/kernel/core_pattern must be core.%p for this test"
	exit 0
fi

[[ $(ulimit -c) != "0" ]] || fatal "core file size limit is 0"

[[ -n $OBJDIR ]] || fatal "\$OBJDIR must be set"
cd $OBJDIR || fatal "could not cd $OBJDIR"
echo "Running test program ... \c"
rm -f test.out
./ucore_test > test.out 2>/dev/null &
pid=$!
wait $pid >/dev/null 2>&1
wstat=$?
echo "done"

echo "Verifying status ... \c"
[[ $wstat = $((128 + 11)) ]] && echo "SIGSEGV" || \
    fail "unexpected exit status $wstat" >& 2

function readelf_phdrs
{
	readelf -W -l $1 | grep -v $2 | \
	    awk '$1=="LOAD" { print $3, $6, $7, $8, $9, $10 }'
}

function readgdb_stats
{
	gdb -q -x /dev/stdin "$@" <<-EOF 2>/dev/null
	    info registers
	    backtrace
	    print rodata
	    print bss
	    print heap
	    print stk
	    quit
	EOF
}

#
# We need to omit the stack during the comparison because dumping the core
# from libucore, before we return, will push the siginfo_t and ucontext_t
# and therefore may end up lowering the bottom of the stack by one page.
# The test program interrogates itself to figure out its stack base and
# prints that to stdout.
#
stk1=$(cat test.out | grep '^stackbase=' | cut -d= -f2)
[[ -n $stk1 ]] || fatal "could not find stackbase= in test program output"

stk2=$(($stk1 + 0x1000))

stk1=$(printf "0x%16llx\n" $stk1)
stk2=$(printf "0x%16llx\n" $stk2)

echo "Comparing ELF content ... \c"
readelf_phdrs core.$pid $stk1 $stk2 >kphdrs.$pid
readelf_phdrs ucore.$pid $stk1 $stk2 >uphdrs.$pid
diff kphdrs.$pid uphdrs.$pid && echo "match" || fail "elf mismatch"

echo "Comparing GDB status ... \c"
readgdb_stats ./ucore_test core.$pid >kgdb.$pid
readgdb_stats ./ucore_test ucore.$pid >ugdb.$pid
diff kgdb.$pid ugdb.$pid && echo "match" || fail "gdb mismatch"

rm -f test.out core.$pid ucore.$pid kphdrs.$pid uphdrs.$pid kgdb.$pid ugdb.$pid
exit $errs
