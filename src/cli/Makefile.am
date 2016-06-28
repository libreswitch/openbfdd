#**************************************************************************
# Copyright (c) 2016 LinkedIn Corp.
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
#
# Author: Ravi Jonnadula
#
# Process this file with Automake to create Makefile.in

#*************************************************************************

AM_CFLAGS =  ${OPSCLI_CFLAGS}
AM_CFLAGS += -I${top_srcdir}/include
AM_CFLAGS += -I$(LOCAL_SYSROOT_DIR)/usr/local/include/ovs -DOPS
AM_CFLAGS += -I $(top_builddir)/include
AM_CFLAGS += -I$(OVS_INCLUDE)
AM_CFLAGS += -I $(top_builddir)/lib

libdir=${prefix}/lib/cli/plugins

lib_LTLIBRARIES = libbfd_cli.la
libbfd_cli_la_SOURCES = bfd_vty.c vtysh_ovsdb_bfd_context.c
libbfd_cli_la_LDFLAGS =  -avoid-version

install-exec-hook:
	@(cd $(DESTDIR)$(libdir) && $(RM) $(lib_LTLIBRARIES))
