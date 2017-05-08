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

LIB := vmem
CFLAGS += -Wno-missing-field-initializers
LDLIBS += -lunuma -lhrtime -ltree -lpthread -ldl

CFLAGS += -I../libtree
CFLAGS += -I../libhrtime
CFLAGS += -I../libunuma

LDLIBS += -L../libtree
LDLIBS += -L../libhrtime
LDLIBS += -L../libunuma

SRCS :=			\
	vmem.c		\
	vmem_cd.c	\
	vmem_cpuid.c	\
	vmem_debug.c	\
	vmem_heap.c	\
	vmem_libc.c	\
	vmem_magazine.c	\
	vmem_mmap.c	\
	vmem_object.c	\
	vmem_printf.c	\
	vmem_root.c	\
	vmem_seg.c	\
	vmem_slab.c	\
	vmem_sleep.c	\
	vmem_thread.c	\
	vmem_unuma.c	\
	vmem_variable.c	\
	vmem_verbose.c

include ../Makefile.lib
