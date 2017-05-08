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
# Qat - a Quality Assurance Tool
#       a spirit in the oral mythology of the Banks Islands of Melanesia
#       a chewable stimulant derived from the catha edulis plant
#       a really useful word to know when playing Scrabble
#
# 1. Introduction
#
# Qat is a flexible and simple execution engine for unit tests.  It allows a
# development team to develop hierarchies of test programs in any language or
# framework, and quickly integrate these tests into multiple structured
# hierarchies of units and passes.  Qat also is designed to simplify the data
# gathering and debugging process for developers, and to simplify statistics
# gathering and automated execution for QA teams and release engineering.  In
# particular it provides complete integration with the Jenkins scheduler tool.
#
# 2. Abstractions
#
# The basic Qat abstractions are a test, which is something Qat can execute
# that has a pass (zero) or fail (non-zero) status, and is written in any
# language such as bash or python or is provided as an executable; a unit,
# which is a file containing a list of Qat directives to run tests; and a pass,
# which is a file containing a list of Qat directives to run tests or units.
# Developers create a Qat hierarchy by organizing tests, units, and passes
# along with any supporting code into a directory tree called the Qat tree.
#
# 3. Directives
#
# Qat units and passes are in fact simple bash shell scripts which can use
# any of the following reserved words:
#
# init - run something from the init/ subdirectory at start of this file
# fini - run something from the fini/ subdirectory at end of this file
# info - print human-readable synopsis of this file
# conf - push a conf directive for this file and its children
# need - evaluate a dependency of this file and abort if not satisfied
# test - run something from the test/ subdirectory
# pass - run something from the pass/ subdirectory
# unit - run something from the unit/ subdirectory
#
# The Qat tree is expected to have these subdirectories at the top of it,
# but developers are free to organize any directory hierarchy below that.
#
# 4. Jenkins Integration
#
# Qat is designed to run from within the Jenkins automated execution framework
# and report its status back to Jenkins via the JUnit.xml output format, which
# enables Jenkins to display an organized visual hierarchy of results and plot
# statistics on test results over time.  For more information, refer to:
#
# [1] https://wiki.jenkins-ci.org/display/JENKINS/Building+a+software+project
# [2] https://svn.jenkins-ci.org/trunk/hudson/dtkit/...
#
# The JUnit.xml schema being used by this version of Qat is saved in the source
# tree here as qat.xsd and the Qat self-test will verify XML output against it.
# The Qat -J option is used to indicate that Qat is running under Jenkins.
#
# 5. Workspace and Environment
#
# Qat will attempt to determine if it is in a git workspace and run binaries
# and tests from there; otherwise it will use a system default path, or it
# needs to be told where to find things using -R and -P command-line options.
# When Qat executes units, passes, and tests, it will set up a standard set
# of environment variables for tools and for Qat itself: these are kept in
# the one common function qat_putenv(), below.  Please keep all future changes
# in this area confined to this function and not scattered throughout.
#
# 6. Implementation Notes
#
# Shell expansion ordering does not provide a convenient means for storing
# file descriptor numbers in variables, so we resort to hard-coding these:
#
# < 0 - stdin is left unchanged by qat and keeps us on the controlling tty
# <>1 - stdout to a fifo on which tee is writing to stdout (3) and log files
# <>2 - stderr to a fifo on which tee is writing to stdout (3) and log files
#  >3 - copy of the original stdout for tee and for bypassing logging
#  >4 - copy of the fifo stdout for qat_echo and qat_warn to use in children
#
# Qat itself is designed to be "friendly" with respect to facilities in sw-main
# such as libvmem, but should not be too closely intertwined with any
# particular piece of software we're testing; so please try to place truly
# generic enhancements in Qat but keep subsystem-specific stuff in the trees.
#

set -o pipefail
shopt -s execfail
shopt -s extglob
shopt -s nullglob
shopt -s xpg_echo

export PATH=/opt/tools/bin:/bin:/usr/bin:/sbin:/usr/sbin
export TERM=${TERM:-dumb}

ulimit -c unlimited
umask 022

declare -r QAT_PASS=0
declare -r QAT_FAIL=1
declare -r QAT_ERRS=2
declare -r QAT_NEED=3
declare -r QAT_SKIP=4
declare -r QAT_USAGE=5
declare -r QAT_SIG0=128

declare -r QAT_TAGS=(
    [$QAT_PASS]=PASS
    [$QAT_FAIL]=FAIL
    [$QAT_ERRS]=ERRS
    [$QAT_NEED]=NEED
    [$QAT_SKIP]=SKIP
)

declare -r QAT_TAG_TOD0=0
declare -r QAT_TAG_TOD1=1
declare -r QAT_TAG_SECS=2
declare -r QAT_TAG_STAT=3
declare -r QAT_TAG_FILE=4
declare -r QAT_TAG_ARGS=5

#
# Convert the signal list into $SIGxxx variables that are set to the signal
# numbers and a QAT_SIGS=([n]=xxx ...) array that converts numbers to names
#
eval declare -r $(trap -l|sed 's/[-+]//g;s/ *\([0-9]*\)) \([A-Z0-9]*\)/\2=\1/g')
siglist=$(trap -l|sed 's/[-+]//g;s/ *\([0-9]*\)) \([A-Z0-9]*\)/[\1]=\2/g')
eval declare -r QAT_SIGS='('"$siglist"')'
unset siglist

declare -i qat_tops=0
declare -a qat_info
declare -a qat_file
declare -a qat_line
declare -a qat_type
declare -a qat_fini

declare -a qat_sums
declare -a qat_tagv


declare -r qat_arg0=$(basename $0)
declare -r qat_argv="$@"
declare -r qat_conf='qat.conf'
declare -r qat_core='qat.core'
declare -r qat_env='qat.env'
declare -r qat_fifo='qat.fifo'
declare -r qat_fio='fio.json'
declare -r qat_host=$(uname -n)
declare -r qat_log='qat.log'
declare -r qat_opts=':cCeEfFg:i:j:JkKl:nNo:O:qP:r:R:s:S:tu:vVx:X'
declare -r qat_path='opt/dssd/lib/qat usr/lib/qat'
declare -r qat_pid='qat.pid'
declare -r qat_ppid=$$
declare -r qat_result="qat.$USER.XXXXXX"
declare -r qat_stat='qat.stat'
declare -r qat_tag='qat.tag'
declare -r qat_width=70
declare -r qat_xid='qat.xid'
declare -r qat_xml='qat.xml'
declare -r qat_max_xml_logged=65536

qat_cdir=$PWD
qat_git=${GIT_DIR:-$(git rev-parse --show-toplevel 2>/dev/null)}
qat_iter=0
qat_list=
qat_secs=0
qat_redir='1>>$qat_log 2>&1'
qat_rval=$QAT_PASS
qat_skipfile='qat.skip'
qat_tee=0
qat_tod0=$(date '+%FT%T')
qat_tod1='-'
qat_tree=
qat_vers=
qat_vpkg=dssd-client
qat_wdid=0

opt_c=false
opt_C=false
opt_e=false
opt_E=false
opt_f=false
opt_F=false
opt_g=
opt_i=1
opt_j=
opt_J=
opt_k=false
opt_K=false
opt_l=
opt_n=false
opt_o=()
opt_N=
opt_O=/dev/null
opt_P="$qat_path"
opt_q=false
opt_r=${TMPDIR:-/tmp}
opt_R="$qat_git/proto /"
opt_s=
opt_S=/dev/null
opt_t=false
opt_u=
opt_v=false
opt_V=
opt_x=qat.xsd
opt_X=

function qat_xml_escape
{
	sed "
	    s/\&/\&amp;/g
	    s/\"/\&quot;/g
	    s/'/\&apos;/g
	    s/</\&lt;/g
	    s/>/\&gt;/g
            s/\o033.[0-9]*m//g
	" "$@"  | LANG=en_US.UTF-8 col -b | head -c $qat_max_xml_logged
}

function qat_xml_strip
{
	sed '
	    /^<!--/,/^-->/d
	    s/^ *hostname=".*"$//g
	    s/^ *name=".*"$//g
	    s/^ *package=".*"$//g
	    s/^ *time.*=".*"$//g
	    s:/[^ 	]*/qat[0-9]\{1,\}/:$qat_root/:g
	' "$@"
}

function qat_xml_testcase
{
	local rv=${qat_tagv[$QAT_TAG_STAT]}
	local tag_args=$(qat_xml_escape <<<${qat_tagv[$QAT_TAG_ARGS]})

	echo "<testcase"
	echo " name=\"${qat_tagv[$QAT_TAG_FILE]} $tag_args\""
	echo " time=\"${qat_tagv[$QAT_TAG_SECS]}\""
	echo " status=\"$rv\""
	echo ">"

	case $rv in
	$QAT_FAIL)
	    echo "<failure message=\"test failure\" type=\"$rv\">"
	    echo "see system-out below for details\n</failure>"
	    ;;
	$QAT_ERRS)
	    echo "<error message=\"test errors\" type=\"$rv\">"
	    echo "see system-out below for details\n</error>"
	    ;;
	$QAT_SKIP)
	    echo "<skipped/>"
	    ;;
	esac

	echo "<system-out>"
	qat_xml_escape $qat_log
	echo "</system-out>"
	echo "</testcase>"
}

function qat_xml_testsuite
{
	local tsid=$1; shift
	local sums=($*)
	local name

	for ((i = 0; i <= $qat_tops; i++)) {
		name="$name/${qat_file[$i]%.qat}"
	}

	echo "<testsuite"
	echo " name=\"${name##//}\""
	echo " tests=\"$(qat_sums_total ${sums[*]})\""
	echo " failures=\"${sums[$QAT_FAIL]}\""
	echo " errors=\"${sums[$QAT_ERRS]}\""
	echo " time=\"${qat_tagv[$QAT_TAG_SECS]}\""
	echo " disabled=\"${sums[$QAT_NEED]}\""
	echo " skipped=\"${sums[$QAT_SKIP]}\""
	echo " timestamp=\"${qat_tagv[$QAT_TAG_TOD1]}\""
	echo " hostname=\"$qat_host\""
	echo " id=\"$tsid\""
	echo " package=\"$qat_vers\""
	echo ">"

	if [[ -s $qat_conf ]]; then
		echo "<properties>"
		sed -n 's:^\(.*\)=\(.*\)$:<property name="\1" value="\2" />:p' \
		    $qat_conf
		echo "</properties>"
	fi

	find . -depth -name qat.testcase.xml -print | sort | xargs cat
	echo "<system-out>"
	qat_xml_escape $qat_log
	echo "</system-out>"
	echo "</testsuite>"
}

function qat_xml_testsuites
{
	echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"

	echo "<!--\n"
	echo "Quality Assurance Tool"
	echo "Copyright $(date '+%Y') Dell Inc. or its subsidiaries.  \c"
	echo "All Rights Reserved."
	echo "Use is subject to license terms."
	qat_footer
	echo "-->"

	#
	# In our version of the JUnit schema, the skipped count is only in the
	# testsuite element but not here at the top, so we add skips to the
	# disabled count such that tests minus all others yields the pass count
	#
	local d=$((${qat_sums[$QAT_NEED]} + ${qat_sums[$QAT_SKIP]}))

	echo "<testsuites"
	echo " name=\"${JOB_NAME:-${opt_u:-$qat_tree}}\""
	echo " time=\"$qat_secs\""
	echo " tests=\"$(qat_sums_total ${qat_sums[*]})\""
	echo " failures=\"${qat_sums[$QAT_FAIL]}\""
	echo " disabled=\"$d\""
	echo " errors=\"${qat_sums[$QAT_ERRS]}\""
	echo ">"

	find . -depth -name qat.testsuite.xml -print | sort | xargs cat
	echo "</testsuites>"
}

function qat_usage
{
	[[ $# -gt 0 ]] && echo "$qat_arg0: $*"

	echo "Usage: $qat_arg0 [-eEfFJkKnNqtvVX] [-g xml] [-i iter] [-j xml]"
	echo "\t[-l log] [-o opt=val] [-O conf] [-P path] [-r resdir] [-R root]"
	echo "\t[-s skip-item] [-S skip-file] [-u utag] [-x xsd]"
	echo "\t[<pass> | pass/<name>.qat | unit/<name>.qat | <test-path> ...]}"
	echo
	echo "\t-c [-r resdir] [-Cv] [<qatroot-path> ...]"

	echo

	echo "\t-c  collate qat output from last failure instead of run tests"
	echo "\t-C  show directory contents when collating qat data"
	echo "\t-e  show execution errors in addition to logging"
	echo "\t-E  stop tests on the first execution error"
	echo "\t-f  show flow control tags as tests run"
	echo "\t-F  stop tests on the first test failure"
	echo "\t-g  verify results against golden JUnit.xml"
	echo "\t-i  set iteration count (default=1)"
	echo "\t-j  write a copy of the JUnit.xml log to the specified file"
	echo "\t-J  run under Jenkins and propagate JUnit.xml log to Jenkins"
	echo "\t-k  keep test results directory even if PASS"
	echo "\t-K  do not keep test results directory even if FAIL"
	echo "\t-l  write a copy of the text log to the specified file"
	echo "\t-n  read units and passes but do not execute tests"
	echo "\t-N  pass -n to scripts for shell syntax checking"
	echo "\t-o  add option to list of initial conf options"
	echo "\t-O  read initial list of conf options from file"
	echo "\t-q  show file pathnames instead of status lines"
	echo "\t-P  set path of places to look for the test tree"
	echo "\t-r  set result directory root (default=\$TMPDIR)"
	echo "\t-R  set root directory for test tree path expansion"
	echo "\t-s  skip specified test, unit, or pass (relative to tree)"
	echo "\t-S  skip all of the items specified in a skip file"
	echo "\t-t  show timestamp tags as tests run"
	echo "\t-u  set user-defined tag for this job (default=\$JOB_NAME)"
	echo "\t-v  show stdout and stderr from tests in addition to logging"
	echo "\t-V  pass -v to scripts for shell verbose output"
	echo "\t-x  set path to xml schema definition file"
	echo "\t-X  pass -x to scripts for shell debug output"

	exit $QAT_USAGE
}

function qat_line
{
	for ((i = 0; i < $1; i++)) {
		echo "$2\c"
	}
}

function qat_pct
{
	local p=$(echo "scale=4; $1 / $2 * 100" | bc -q 2>/dev/null)
	printf '%d = %5.1f%%' "$1" "${p:-0}"
}

function qat_env
{
	local secs=${qat_secs:-0}
	local t_ss=$(($secs % 60))
	local secs=$(($secs / 60))
	local t_mm=$(($secs % 60))
	local t_hh=$(($secs / 60))

	printf "  name: %s\n" "${JOB_NAME:-${opt_u:-$qat_tree}}"
	printf "  vers: %s\n" "$qat_vers"
	printf "  argv: %s %s\n" "$qat_arg0" "$qat_argv"
	printf "  list: %s\n\n" "$qat_list"
	printf "  path: %s\n\n" "$PATH"

	if [[ -n "$qat_git" ]]; then
		printf "  git_dir: %s\n" $qat_git
		printf "  git_url: %s\n" $GIT_URL
		printf "  git_branch: %s\n" $GIT_BRANCH
		printf "  git_commit: %s\n\n" $GIT_COMMIT
	fi

	if [[ -n "$opt_J" ]]; then
		printf "  jenkins_build_number: %s\n" $BUILD_NUMBER
		printf "  jenkins_build_id: %s\n" $BUILD_ID
		printf "  jenkins_build_url: %s\n" $BUILD_URL
		printf "  jenkins_node_name: %s\n" $NODE_NAME
		printf "  jenkins_job_name: %s\n" $JOB_NAME
		printf "  jenkins_workspace: %s\n\n" $WORKSPACE
	fi

	printf "  node: %-20s  sys: %s\n" "$qat_host" "$(uname -sr)"
	printf "  user: %-20s  pid: %s\n" $(id -nu) $qat_ppid
	printf "  root: %-20s tree: %s\n" $qat_root $qat_tree
	printf " start: %-20s stop: %s (%02d:%02d:%02d)\n" \
	    $qat_tod0 $qat_tod1 $t_hh $t_mm $t_ss
}

function qat_header
{
	printf "\n"
	tput bold >&3; printf "Quality Assurance Tool\n"; tput sgr0 >& 3
	printf "Copyright $(date '+%Y') Dell Inc. or its subsidiaries.  "
	printf "All Rights Reserved.\n"
	printf "Use is subject to license terms.\n"
	printf "\n"
	qat_env
	qat_line $qat_width _
	printf "\n\n"
}

function qat_footer
{
	$opt_q && return
	qat_line $qat_width _
	printf "\n\n"
	qat_env
	printf "\n"
	$opt_n && return

	local p=${qat_sums[$QAT_PASS]}
	local f=${qat_sums[$QAT_FAIL]}
	local t=$(($p + $f))
	local d=$((${qat_sums[$QAT_NEED]} + ${qat_sums[$QAT_SKIP]}))
	local n=$((${qat_sums[$QAT_ERRS]} + $d + $t))

	printf " exec: %-20s  iter: %d of %d\n" \
	    "$(qat_pct $t $n)" $qat_iter $opt_i

	printf " pass: %-20s  fail: %s\n" \
	    "$(qat_pct $p $t)" "$(qat_pct $f $t)"

	printf " errs: %-20s  core: %d\n" \
	    ${qat_sums[$QAT_ERRS]} $(wc -l <$qat_root/$qat_core)

	printf " need: %-20s  skip: %s\n\n" \
	    ${qat_sums[$QAT_NEED]} ${qat_sums[$QAT_SKIP]}

	printf " stat: %s\n\n" ${QAT_TAGS[$qat_rval]}
}

function qat_verify
{
	local r0=$opt_g
	local r1=$qat_root/$qat_xml
	local rv=$QAT_PASS

	qat_line $qat_width _
	echo "\n"

	for d in $qat_path; do
		[[ -f $opt_R/$d/$opt_x ]] || continue
		opt_x=$opt_R/$d/$opt_x
		break
	done

	echo " xml lint master: \c"
	xmllint --noout --schema $opt_x $r0 2>&1 || rv=$QAT_FAIL

	echo " xml lint output: \c"
	xmllint --noout --schema $opt_x $r1 2>&1 || rv=$QAT_FAIL

	echo " xml diff verify: \c"
	qat_xml_strip $r0 >$qat_root/qat.xml.0
	qat_xml_strip $r1 >$qat_root/qat.xml.1

	diff $qat_root/qat.xml.0 $qat_root/qat.xml.1 || rv=$QAT_FAIL
	echo "${QAT_TAGS[$rv]}\n"

	qat_rval=$rv
	return $rv
}

function qat_rehash
{
	local d='[0-9]*'
	local r="$1"
	local p

	export PATH=$PATH:$r/usr/bin:$r/opt/dssd/bin
	p=$(python -V 2>&1 | sed -n "s/Python \($d.$d\)\(.$d\)*/python\1/p")
	export PYTHONPATH=$qat_tree/py:$r/usr/lib64/${p:-python}/site-packages
}

function qat_putenv
{
	unset BASH_ENV
	unset ENV
	unset LIBFLOOD_TUNE

	export CK_DEFAULT_TIMEOUT={CK_DEFAULT_TIMEOUT:-60}
	export CK_TIMEOUT_MULTIPLIER={CK_TIMEOUT_MULTIPLIER:-10}
	export CK_VERBOSITY=${CK_VERBOSITY:-verbose}
	export FF_AUDIT=${FF_AUDIT:-all}
	export UCORE_OPTIONS=${UCORE_OPTIONS:-user,nokernel}
	export UCORE_PATH=core.%e.%p
	export VMEM_DEBUG=${VMEM_DEBUG:-all}

	export QAT_CONF=$PWD/$qat_conf
	export QAT_HOST=$qat_host
	export QAT_PPID=$qat_ppid
	export QAT_SHMDIR=/dev/shm/qat$qat_ppid
	export QAT_TMPDIR=$PWD
	export QAT_TREE=$qat_tree

	export LIBFLOOD_CONF=$QAT_CONF

	env >$qat_env
}

function qat_sums_total
{
	local t=0

	for ((i = 0; i < $QAT_USAGE; i++)) {
		t=$(($t + $1))
		shift
	}

	echo $t
}

function qat_sums_reset
{
	for ((i = 0; i < $QAT_USAGE; i++)) {
		qat_sums[$i]=0
	}
}

function qat_tagv_init
{
	local file="$1"; shift
	local args="$*"

	qat_tagv=(
	[$QAT_TAG_TOD0]=$(date '+%FT%T')
	[$QAT_TAG_TOD1]=
	[$QAT_TAG_SECS]=$SECONDS
	[$QAT_TAG_STAT]=
	[$QAT_TAG_FILE]="$file"
	[$QAT_TAG_ARGS]="$args"
	)
}

function qat_tagv_fini
{
	local t0=${qat_tagv[$QAT_TAG_SECS]}
	local t1=$SECONDS

	qat_tagv[$QAT_TAG_TOD1]=$(date '+%FT%T')
	qat_tagv[$QAT_TAG_SECS]=$(($t1 - $t0))
	qat_tagv[$QAT_TAG_STAT]=$1

	echo "${qat_tagv[*]}" >$qat_tag
	return $1
}

function qat_start
{
	qat_secs=$SECONDS
	qat_sums_reset
}

function qat_stop
{
	qat_tod1=$(date '+%FT%T')
	qat_secs=$(($SECONDS - $qat_secs))
	qat_qstat qat_sums
	qat_rval=$?

	cd $qat_root
	find . -name core\* -type f -print >$qat_core
	[[ $qat_rval -eq $QAT_PASS && -s $qat_core ]] && qat_rval=$QAT_ERRS
	cd $qat_cdir
}

function qat_cleanup
{
	local r

	if [[ $qat_tee -ne 0 ]]; then
		exec 1>&- 2>&- 4>&-
		wait $qat_tee
		qat_tee=0
		rm -f $qat_root/$qat_fifo
		exec 1>&3 2>&3
	fi

	[[ $qat_rval -eq $QAT_PASS ]] && r=true || r=false

	$opt_k && r=false # -k so keep regardless of status
	$opt_K && r=true  # -K so kill regardless of status

	$r && [[ $qat_root != / ]] && rm -rf "$qat_root"
}

function qat_echo
{
	[[ $opt_v = false && $BASH_SUBSHELL -gt 0 ]] && echo "$*" >& 4
	echo "$*"
	return 0
}

function qat_warn
{
	echo "$qat_arg0: $*" >& 2
	return 0
}

function qat_die
{
	trap - EXIT
	qat_rval=$QAT_ERRS
	qat_warn "$@"
	qat_cleanup
	exit $qat_rval
}

function qat_err
{
	$opt_q || qat_echo ${QAT_TAGS[$QAT_ERRS]}
	qat_sums[$QAT_ERRS]=$((${qat_sums[$QAT_ERRS]} + 1))
	exit $QAT_ERRS
}

function qat_errx
{
	local file=${qat_file[$qat_tops]}
	local line=${qat_line[$qat_tops]}

	if $opt_e; then
		echo "qat ERROR: \"$file\", line $line: $@" >& 4
	else
		echo "qat ERROR: \"$file\", line $line: $@" >& 2
	fi

	echo $QAT_ERRS # for use with return $( ) statement
	qat_sums[$QAT_ERRS]=$((${qat_sums[$QAT_ERRS]} + 1))
	$opt_E && exit $QAT_ERRS
	return $QAT_ERRS
}

function qat_intr
{
	echo "\r\n" >& 3
	qat_errx "$$.$BASH_SUBSHELL interrupted at user request" >/dev/null
	qat_exit $QAT_ERRS
}

function qat_exit
{
	trap - EXIT
	qat_stop

	$opt_n && qat_rval=$QAT_PASS
	[[ $# -gt 0 ]] && qat_rval=$1

	cd $qat_root
	qat_xml_testsuites >$qat_xml
	cd $qat_cdir

	if [[ -n "$opt_j" ]]; then
		cp $qat_root/$qat_xml $opt_j || qat_rval=$QAT_ERRS
	fi

	if [[ -n "$opt_J" ]]; then
		mkdir -p $(dirname $opt_J) >/dev/null 2>&1
		cp $qat_root/$qat_xml $opt_J || qat_rval=$QAT_ERRS
	fi

	qat_footer
	[[ -n "$opt_g" ]] && qat_verify
	qat_cleanup
	exit $qat_rval
}

#
# The exit status for qat_push and qat itself is determined as follows: if any
# execution failed, we fail; otherwise if anything passed we pass; otherwise
# just walk the exit status vector in order and return the first non-zero item.
#
function qat_qstat
{
	for stat in $QAT_FAIL $QAT_ERRS $QAT_PASS; do
		[[ $(eval echo '${'$1'[$stat]}') -gt 0 ]] && return $stat
	done

	for ((stat = 0; stat < $QAT_USAGE; stat++)) {
		[[ $(eval echo '${'$1'[$stat]}') -gt 0 ]] && return $stat
	}

	return $QAT_PASS
}

function qat_done
{
	$opt_q || qat_echo DONE
}

function qat_pass
{
	qat_sums[$QAT_PASS]=$((${qat_sums[$QAT_PASS]} + 1))
	$opt_q || qat_echo ${QAT_TAGS[$QAT_PASS]}
}

function qat_fail
{
	local rv=$1
	[[ $rv -ge $QAT_USAGE ]] && rv=$QAT_FAIL
	qat_sums[$rv]=$((${qat_sums[$rv]} + 1))

	local st=${QAT_TAGS[$rv]}
	[[ $1 -gt $QAT_SIG0 ]] && \
	    st="$st (${QAT_SIGS[$(($1 - $QAT_SIG0))]#SIG})"
	$opt_q || qat_echo "$st"

	[[ $rv -eq $QAT_FAIL ]] && $opt_F && exit $rv
	[[ $rv -eq $QAT_ERRS ]] && $opt_E && exit $rv

	return $rv
}

# Look through qat result directories for failures and
# list files and print tag information.
function qat_collate
{
	local f
	local fmt="%19s %4s %s\t%s\t%s\n"
	local qd

	if [[ -z "$qat_list" ]] ; then
		qat_list=$(ls -td ${opt_r}/qat* | head -1)
	fi

	$opt_C || printf "$fmt" DATE STAT PATH FILE ARGS
	for qd in $qat_list ; do
		for f in $(find $qd -name $qat_tag 2>/dev/null) ; do
		    local x=($(<$f))
		    if [[ ${x[$QAT_TAG_STAT]} != 0 ]] ; then
			local d=$(dirname $f)
			if $opt_C ; then
				echo ${x[*]}
				echo d=$d
				ls -lF $d
			else
				printf "$fmt" ${x[$QAT_TAG_TOD1]} \
				    ${x[$QAT_TAG_STAT]} ${d#${qd%%/}/} \
				    ${x[$QAT_TAG_FILE]} ${x[$QAT_TAG_ARGS]}
			fi
			$opt_v && cat $d/$qat_log && echo
		    fi
		done
	done
	exit $QAT_PASS
}

# Generate a fio input file from the file provided  with environment
# variable expansion.
#
# At some point it should be integrated with fiox when that interface stabilizes.
#
function qat_fio
{
	local -r fio_out=fio.json
	local srcpath=$1
	local path=$(basename $1)
	shift

	printf "cat <<EOF\n$(<$srcpath)\nEOF" | bash -p >$path

	# TODO fioflood currently leaking somewhere so VMEM_DEBUG kills us.
	VMEM_DEBUG= fio --output $qat_fio --output-format=json "$@" $path
}

function qat_skip
{
	for ((s = 0; s < ${#qat_skiplist[*]}; s++)) {
		case "$1/$2" in ${qat_skiplist[$s]})
		qat_sums[$QAT_SKIP]=$((${qat_sums[$QAT_SKIP]} + 1))
		$opt_q || qat_echo "$1 $2 ... ${QAT_TAGS[$QAT_SKIP]}"
		return 0 ;;
		esac
	}

	return 1
}

function qat_exec
{
	local type=$1; shift
	local file=$1; shift
	local suff=$(echo $file | sed -n 's/^.*\.\(.*\)$/\1/p')

	if [[ $file =~ ^/ ]]; then
		local path=$file
		file=$(basename $path)
	else
		local path=$qat_tree/$type/$file
	fi

	if $opt_q; then
		qat_echo "$path $*"
	elif [[ $# -gt 0 ]]; then
		qat_echo "$type $file $* ... \c"
	else
		qat_echo "$type $file ... \c"
	fi

	if [[ -n "$suff" && ! -f $path ]]; then
		return $(qat_errx "no such file: $path")
	elif [[ -z "$suff" && ! -x $path ]]; then
		return $(qat_errx "missing or not executable: $path")
	fi

	$opt_n && return 0
	local wdir=$(printf '%03d.%s' $qat_wdid "$file")
	qat_wdid=$(($qat_wdid + 1))
	mkdir -p $wdir || return $(qat_errx "failed to mkdir $wdir")
	pushd $wdir >/dev/null || return $(qat_errx "failed to cd to $wdir")
	qat_tagv_init $type/$file "$@"

	case "$suff" in
	'') eval $path "$@" $qat_redir ;;
	fio) eval qat_fio $path "$@" $qat_redir ;;
	py) eval python $path "$@" $qat_redir ;;
	sh) eval bash -p $opt_N $opt_V $opt_X $path "$@" $qat_redir ;;
	 *) qat_errx "unsupported exec suffix: .$suff" >/dev/null ;;
	esac

	if qat_tagv_fini $? && [[ -f $qat_tree/$type/${file%.$suff}.out ]] && \
	    ! diff $qat_tree/$type/${file%.$suff}.out $qat_log >qat.diff; then
		qat_warn "$type/$file output mismatch: see qat.diff"
		qat_tagv[$QAT_TAG_STAT]=$QAT_FAIL
		echo "${qat_tagv[*]}" >$qat_tag
	fi

	[[ $type = test ]] && qat_xml_testcase >qat.testcase.xml
	popd >/dev/null

	return ${qat_tagv[$QAT_TAG_STAT]}
}

function qat_push
{
	local type="$1"; shift
	local file="${1%%.qat}"; shift
	local path="$qat_tree/$type/$file.qat"

	local wdir=$(printf '%03d.%s' $qat_wdid "$file")
	qat_wdid=$(($qat_wdid + 1))

	[[ -r $path ]] || return $(qat_errx "missing or not readable: $path")
	mkdir -p $wdir || return $(qat_errx "failed to mkdir $wdir")
	cp $qat_conf $wdir/$qat_conf || return $(qat_errx "failed to cp conf")
	pushd $wdir >/dev/null || return $(qat_errx "failed to cd to $wdir")

	qat_tagv_init $type/$file
	$opt_t && qat_echo ${qat_tagv[$QAT_TAG_TOD0]}" \c"
	$opt_f && qat_echo $(qat_line $qat_tops -)"-> \c"

	if $opt_q; then
		qat_echo "$path"
	else
		qat_echo "$type $file - \c"
	fi

	qat_tops=$(($qat_tops + 1))
	qat_info[$qat_tops]=$file
	qat_file[$qat_tops]=$type/$file.qat
	qat_line[$qat_tops]=1
	qat_type[$qat_tops]=$type

	(
	    qat_cdir=$PWD
	    qat_sums_reset
	    qat_fini=()
	    qat_wdid=0

	    echo ${BASHPID:-$qat_pid.$BASH_SUBSHELL} >$qat_pid
	    echo "${qat_sums[*]}" >$qat_stat
	    qat_putenv

	    trap qat_pop EXIT
	    trap "exit $(($QAT_SIG0 + $SIGINT))" INT
	    shopt -u execfail
	    eval exec $qat_redir
	    set $opt_N $opt_V $opt_X --
	    source $path
	)

	[[ -r $qat_stat ]] || return $(qat_errx "stats missing: $path")
	read -a sums <$qat_stat || return $(qat_errx "stat read error: $path")

	for ((i = 0; i < $QAT_USAGE; i++)) {
		qat_sums[$i]=$((${qat_sums[$i]} + ${sums[$i]:-0}))
	}

	qat_qstat sums
	qat_tagv_fini $?

	local tsid=$(<$qat_root/$qat_xid)
	echo $(($tsid + 1)) >$qat_root/$qat_xid
	qat_xml_testsuite $tsid ${sums[*]} >qat.testsuite.xml

	popd >/dev/null
	qat_tops=$(($qat_tops - 1))

	$opt_f && qat_echo "<-"$(qat_line $qat_tops -) "\c"
	$opt_f && $opt_q && qat_echo "$path"
	$opt_q || qat_echo "$type $file = \c"

	return ${qat_tagv[$QAT_TAG_STAT]}
}

function qat_pop
{
	for ((i = ${#qat_fini[*]} - 1; i >= 0; i--)) {
		qat_exec ${qat_fini[$i]} && qat_done
	}

	echo "${qat_sums[*]}" >$qat_cdir/$qat_stat
}

function info
{
	qat_line[$qat_tops]=${BASH_LINENO[0]}
	[[ $# -eq 0 ]] && return $(qat_errx "info: no note specified")
	$opt_q || qat_echo "$*"
	qat_info[$qat_tops]="$*"
}

function init
{
	qat_line[$qat_tops]=${BASH_LINENO[0]}
	[[ $# -eq 0 ]] && return $(qat_errx "init: no file specified")
	qat_exec init "$@" && qat_done || qat_err
}

function fini
{
	qat_line[$qat_tops]=${BASH_LINENO[0]}
	[[ $# -eq 0 ]] && return $(qat_errx "fini: no file specified")
	qat_fini[${#qat_fini[*]}]="fini $@"
}

function conf
{
	qat_line[$qat_tops]=${BASH_LINENO[0]}
	[[ $# -eq 0 ]] && return $(qat_errx "conf: no conf property specified")

	#
	# If the test run had the same parameter specified by -o or -O at the
	# top-level, assume this is a global override for any conf directives.
	#
	[[ "$1" =~ ^([^=]*)= ]] && \
	    grep -qs "^${BASH_REMATCH[1]}=" $qat_root/$qat_conf && return 0

	echo "$@" >>$qat_conf || return $(qat_errx "failed to write $qat_conf")
}

function need
{
	qat_line[$qat_tops]=${BASH_LINENO[0]}
	[[ $# -eq 0 ]] && return $(qat_errx "need: no file specified")
	qat_exec need "$@" && qat_done || qat_fail $QAT_NEED
	[[ $? -eq $QAT_NEED && $BASH_SUBSHELL -gt 0 ]] && exit $QAT_PASS
}

function test
{
	qat_line[$qat_tops]=${BASH_LINENO[0]}
	[[ $# -eq 0 ]] && return $(qat_errx "test: no file specified")
	qat_skip test $1 && return $QAT_SKIP
	qat_exec test "$@" && qat_pass || \
	    qat_fail $(($? < $QAT_SIG0 ? $QAT_FAIL : $?))
}

function unit
{
	qat_line[$qat_tops]=${BASH_LINENO[0]}
	[[ $# -eq 0 ]] && return $(qat_errx "unit: no file specified")
	[[ $# -gt 1 ]] && return $(qat_errx "unit: usage: unit <file.qat>")
	qat_skip unit $1 && return $QAT_SKIP
	qat_push unit "$@" && qat_pass || qat_fail $?
}

function pass
{
	qat_line[$qat_tops]=${BASH_LINENO[0]}
	[[ $# -eq 0 ]] && return $(qat_errx "pass: no file specified")
	[[ $# -gt 1 ]] && return $(qat_errx "pass: usage: pass <file.qat>")
	qat_skip pass $1 && return $QAT_SKIP
	qat_push pass "$@" && qat_pass || qat_fail $?
}

while getopts $qat_opts c; do
	case "$c" in
	c|C|e|E|f|F|J|k|K|n|q|t|v) eval opt_$c='true' ;;
	g|i|j|l|O|P|r|R|S|u|x) eval opt_$c="'"$OPTARG"'" ;;
	N|V|X) eval opt_$c='-'$(echo $c | tr 'A-Z' 'a-z') ;;
	o) opt_o[${#opt_o[*]}]="$OPTARG" ;;
	s) opt_s="$opt_s $OPTARG" ;;
	:) qat_usage "option requires an argument -- $OPTARG" >& 2 ;;
	*) qat_usage "illegal option -- $OPTARG" >& 2 ;;
	esac
done

shift $(($OPTIND - 1))
qat_list="$@"

$opt_c && qat_collate $qat_list

[[ -d "$opt_r" ]] || qat_die "-r (or \$TMPDIR) must be a directory: $opt_r"
qat_root=$(mktemp -d -p ${opt_r} $qat_result)

[[ "$opt_i" =~ ^[0-9]+$ ]] || qat_die "-i requires integer operand: $opt_i"
[[ "$opt_O" =~ ^/ ]] || opt_O="$qat_cdir/$opt_O"
[[ "$opt_S" =~ ^/ ]] || opt_S="$qat_cdir/$opt_S"

[[ -z "$opt_l" ]] || [[ "x$opt_l" =~ ^x/ ]] || opt_l="$qat_cdir/$opt_l"

if [[ -n "$opt_J" ]]; then
	[[ -n "$WORKSPACE" ]] || qat_die "-J requires \$WORKSPACE to be set"
	[[ -n "$JOB_NAME" ]] || qat_die "-J requires \$JOB_NAME to be set"

	[[ -d "$WORKSPACE" ]] || \
	    qat_die "\$WORKSPACE is missing or not a directory: $WORKSPACE"

	qat_git=$WORKSPACE
	opt_J=$WORKSPACE/test-reports/$JOB_NAME.xml
	opt_R=$WORKSPACE/proto
fi

for r in $opt_R; do
	for d in $opt_P; do
		[[ -d ${r%/}/${d#/} ]] || continue

		opt_P=${d#/}
		opt_R=${r%/}

		qat_tree=${r%/}/${d#/}
		qat_rehash ${r%/}

		break 2
	done
done

[[ -d "$qat_tree" ]] || qat_die "failed to locate test tree: use -R and/or -P"
[[ -n "$qat_list" ]] || qat_list=$(find $qat_tree/pass -name \*.qat | sort)
[[ -n "$qat_list" ]] || qat_die "no passes specified or found in $qat_tree"

if [[ $r = $qat_git/proto ]]; then
	export GIT_WORK_TREE=${GIT_WORK_TREE:-$qat_git}
	export GIT_DIR=${GIT_DIR:-$GIT_WORK_TREE/.git}
	export GIT_URL=${GIT_URL:-$(git config --get remote.origin.url)}
	export GIT_BRANCH=${GIT_BRANCH:-$(git rev-parse --abbrev-ref HEAD)}
	export GIT_COMMIT=${GIT_COMMIT:-$(git rev-parse --verify HEAD)}
fi

if [[ -f $r/../Makefile.version ]]; then
	qat_vers=$(make -s -f $r/../Makefile.version VG_VERSION 2>/dev/null)
elif [[ -d $r/../var/lib/rpm ]]; then
	qat_vers=$(rpm -q --root=$r/.. --qf=%{SOURCERPM} $qat_vpkg 2>/dev/null)
fi

[[ -n "$qat_vers" ]] && qat_vers=${qat_vers#VG_VERSION=}
[[ -n "$VG_VERSION" ]] && qat_vers=$VG_VERSION
[[ -z "$qat_vers" ]] && qat_vers=unknown

set -- $qat_list
qat_list=

for f in "$@"; do
	if [[ $f =~ \.qat$ ]]; then
		f=${f#$qat_tree/}
		[[ $f =~ ^/ ]] && qat_die "qat path not relative: $f"
		[[ $f =~ ^\.\.?/ ]] && qat_die "qat path not relative: $f"
		[[ $f =~ / ]] || f="pass/$f" # default type to pass/
		qat_list="$qat_list $f"
	elif [[ $f =~ ^/ && -f $f ]]; then
		qat_list="$qat_list $f"
	elif [[ $f =~ ^\.\.?/ && -f $f ]]; then
		qat_list="$qat_list $qat_cdir/$f"
	elif [[ -f ./$f ]]; then
		qat_list="$qat_list $qat_cdir/$f"
	elif [[ -f $qat_tree/$f ]]; then
		qat_list="$qat_list $qat_tree/$f"
	elif [[ -f $qat_tree/$f.qat ]]; then
		qat_list="$qat_list $f.qat"
	elif [[ -f $qat_tree/pass/$f.qat ]]; then
		qat_list="$qat_list pass/$f.qat"
	else
		qat_die "no such file: $f"
	fi
done

qat_list=${qat_list## }
dirs -c

trap qat_intr INT
[[ -d "$qat_root" ]] || qat_die "failed to create qat_root $qat_root"
cd $qat_root || qat_die "failed to cd to $qat_root"
$opt_v && qat_redir='2>&1 | tee -a $qat_log'

cp $opt_O $qat_conf || qat_die "failed to cp $opt_O to $qat_root"
touch $qat_log || qat_die "failed to init log file: $qat_log"
[[ -z "$opt_l" ]] || touch $opt_l || qat_die "failed to init log file: $opt_l"
cp $opt_S $qat_skipfile || qat_die "failed to cp $opt_S to $qat_root"
echo 0 >$qat_xid || qat_die "failed to init xid file in $qat_root"
echo $qat_ppid >$qat_pid || qat_die "failed to init pid file in $qat_root"
qat_putenv || qat_die "failed to init env file in $qat_root"

shopt -u nullglob
for ((o = 0; o < ${#opt_o[*]}; o++)); do
	echo ${opt_o[$o]} >>$qat_conf || qat_die "failed to init conf file"
done
for s in $opt_s; do
	echo "$s" >>$qat_skipfile || qat_die "failed to init skip file"
done
shopt -s nullglob

egrep -v '^$|^#' $qat_skipfile | nl -p -v 0 -n ln -s = | \
    sed "s/\([0-9]*\) *=\(.*\)/[\1]='\2'/" >$qat_skipfile.sh

eval declare -r qat_skiplist='('"$(<$qat_skipfile.sh)"')'

rm -f $qat_fifo $qat_log >/dev/null 2>&1
mkfifo $qat_fifo || qat_die "failed to create fifo: $qat_fifo"
exec 3>&1
exec 1<>$qat_fifo 2>&1
tee -a $qat_log $opt_l <$qat_fifo >&3 2>&3 &
qat_tee=$!
exec 4>&1

$opt_q || qat_header
trap qat_exit EXIT
qat_start

while [[ $qat_iter -lt $opt_i ]]; do
	for f in $qat_list; do
		if [[ $f =~ \.qat$ ]]; then
			type=$(echo "$f" | cut -d/ -f1)
			file=$(echo "$f" | cut -d/ -f2-)
			qat_push $type $file && qat_pass || qat_fail $?
		else
			qat_file[$qat_tops]=$f
			qat_line[$qat_tops]=unknown
			qat_exec test $f && qat_pass || \
			    qat_fail $(($? < $QAT_SIG0 ? $QAT_FAIL : $?))
		fi
	done
	qat_iter=$(($qat_iter + 1))
done

qat_exit
