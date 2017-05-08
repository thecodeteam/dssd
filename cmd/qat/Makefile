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

all clean clobber:
	# shell script build, nothing to do

#
# For the self-test, give qat all the arguments necessary to run inside of the
# build environment and use the test tree located here in our source directory.
# To generate the golden result file test/test.xml when qat itself changes,
# replace -g with -j (keeping the argument the same) -- this will report FAIL
# as a result of the test tree itself generating failures, but will leave XML.
# To debug -g failures, change -K to -k in TEST_ARGS to retain /tmp/qat*
#
TEST_ARGS_qat := \
    -g $(SRCDIR)/test/test.xml \
    -K \
    -P ../$(SRCDIR)/test \
    -R $(TOPDIR_FULL)/proto \
    -S $(SRCDIR)/test/test.skip \
    -u qat-test-self \
    -x $(SRCDIR)/qat.xsd
