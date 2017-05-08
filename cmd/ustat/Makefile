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
include ../../Makefile.x86_64

CMD := ustat
SRCS := ustat.c

CFLAGS += -I../../lib/libunuma
CFLAGS += -I../../lib/libvmem
CFLAGS += -I../../lib/libbson
CFLAGS += -I../../lib/libustat

LDLIBS += -L../../lib/libhrtime -lhrtime
LDLIBS += -L../../lib/libtree -ltree
LDLIBS += -L../../lib/libunuma -lunuma
LDLIBS += -L../../lib/libvmem -lvmem
LDLIBS += -L../../lib/libbson -lbson
LDLIBS += -L../../lib/libustat -lustat

LDLIBS += -lpthread -lm

include ../Makefile.cmd
