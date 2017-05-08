# DSSD Linux Developer Pro C Toolkit

## Overview
The DSSD Linux `Pro C Toolkit` is a set of C programming libraries and
utilities that were developed in the course of building the DSSD NVMe
storage array datapath, and were essential in achieving the speed and
flexibility of our implementation (>10M IOPS, <100us avg latency, and a 
full-featured object store supporting file, block and key-value interfaces
in only 100K lines of code).

During the course of building DSSD, we felt that some of our low-level C
programming primitives were so generally useful for C coding on Linux that
they merited being designed as standalone, separate libraries and tools.  We
share those components here as open-source in the hope that other projects
may benefit from their design ideas and/or implementation.

## Components
The components currently provided by the toolkit are:

* libbson - bson and json encoder and decoder
* libhrtime - userland timestamp counter access
* libtree - LLRB tree data structure library
* libucore - userland core dump facility for long-running daemon processes
* libunuma - userland programming API for NUMA and hugetlbfs
* libustat - userland statistics library for publication and subscription
* libutrace - userland sub-microsecond tracing and instrumentation engine
* libvmem - userland virtual memory allocator
* libvmem_malloc - libvmem interposition library for malloc and free
* qat - regression test execution engine, compatible with Jenkins
* ustat - userland statistics live and post-mortem query utility

## Interfaces
The public interfaces for each library are found in lib*name*/*name*.h (for
example, libvmem/vmem.h).  The interfaces should be relatively self-
explanatory once you are familiar with the code.  Where applicable, large
block comments are found at the top of the source files with design and
interface documentation.  If you begin using one of the provided libraries
extensively, feel free to contribute Doxygen support to this project.

## Makefiles
The Makefiles provided for this project are a very simple skeleton just to 
show how the source is meant to be built.  They do not constitute a full
implementation of configuring and building a set of shipping libraries.
These components are meant to integrated directly with your build system,
which we assume is using its own set of Makefiles and Make conventions.

## Authors
The components in this toolkit were written and designed by
[Mike Shapiro](https://en.wikipedia.org/wiki/Mike_Shapiro_(programmer))
(libhrtime, libucore, libustat, libutrace, qat, ustat),
[Jeff Bonwick](https://en.wikipedia.org/wiki/Jeff_Bonwick)
(libbson, libtree, libvmem, libvmem_malloc),
and Simon Barrett (libunuma, libhrtime, libustat).

## License
The DSSD `Pro C Toolkit` project is licensed to you under the Apache License,
Version 2.0. Please refer to the LICENSE file for additional information.
