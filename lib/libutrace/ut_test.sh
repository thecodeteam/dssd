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
# Run ut_test with memory checking and leak checking enabled in libvmem.
# Strip out functions offsets +0x which are likely to break if we upgrade
# compilers or change compilation options, and diff the output against
# something we have hand-verified to be corrected for our test program.
#

VMEM_DEBUG=all $OBJDIR/ut_test <$SRCDIR/ut_test.u | \
  sed 's/+0x[0-9a-f]*//' | egrep -v '^(tid|frame)=' | diff -u $SRCDIR/ut_test.out -

# Clean up cores first..
utfile=$PWD/$SRCDIR/ut_test_core.u
rm -f $OBJDIR/core.[0-9]*
if (cd $OBJDIR; VMEM_DEBUG=all ./ut_test 60 ) < $utfile > $OBJDIR/ut_test.out   2>$OBJDIR/ut_test.err ; then
    echo "unexpected success"
    exit 1
fi
count=0
corepat=$OBJDIR/core.[0-9]*
while ! [[ -r $(ls $corepat) ]] ; do
    echo $(date) $PWD $corepat not found
    sleep 1
    ((count+=1))
    if [[ $count -gt 5 ]] ; then
	    exit 1
    fi
done

