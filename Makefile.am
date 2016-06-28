## Process this file with automake to produce Makefile.in.

SUBDIRS      = src/cli
#EXTRA_DIST   = $(DX_CONFIG) include get-version autogen.sh
DIST_SUBDIRS = $(SUBDIRS)

bin_PROGRAMS = bfdd-beacon bfdd-control

if ENABLE_OVSDB
#DEFS = @DEFS@ -DSYSCONFDIR=\"$(sysconfdir)/\"
AM_CPPFLAGS = $(INTI_CFLAGS) $(WARNINGCXXFLAGS) $(OTHERCXXFLAGS)
AM_CPPFLAGS += -I$(top_srcdir)/include
AM_CPPFLAGS += -I $(top_builddir)/include
AM_CPPFLAGS += -I $(top_srcdir)/lib
AM_CPPFLAGS += -I $(top_builddir)/lib
AM_CPPFLAGS += -I$(OVS_INCLUDE)
AM_CPPFLAGS += -DENABLE_OVSDB
AM_LDFLAGS = $(PILDFLAGS)
else
AM_CXXFLAGS = $(INTI_CFLAGS) $(WARNINGCXXFLAGS) $(OTHERCXXFLAGS)
endif

COMMON_INC = common.h utils.h log.h SmartPointer.h threads.h bfd.h standard.h \
             TimeSpec.h Socket.h RecvMsg.h SockAddr.h lookup3.h compat.h \
             AddrType.h Logger.h LogTypes.h LogException.h
COMMON_SRC = $(COMMON_INC) common.cpp utils.cpp log.cpp SmartPointer.cpp threads.cpp bfd.cpp \
             TimeSpec.cpp Socket.cpp RecvMsg.cpp SockAddr.cpp lookup3.cpp compat.cpp \
             AddrType.cpp Logger.cpp LogException.cpp
CONTROL_SRC = bfdd-control.cpp
BEACON_INC = Beacon.h CommandProcessor.h Scheduler.h SchedulerBase.h KeventScheduler.h SelectScheduler.h \
             Session.h hash_map.h
BEACON_SRC = $(BEACON_INC) BeaconMain.cpp Beacon.cpp CommandProcessor.cpp SchedulerBase.cpp KeventScheduler.cpp \
             SelectScheduler.cpp Session.cpp

if ENABLE_OVSDB
BEACON_INC += bfdOvsdbIf.h
BEACON_SRC += bfdOvsdbBackend.cpp bfdOvsdbIf.c
endif

if ENABLE_OVSDB
bfdd_beacon_SOURCES = $(COMMON_SRC) $(BEACON_SRC)
bfdd_beacon_LDADD =  $(INTI_LIBS) -lovscommon -lovsdb -lpthread
else
bfdd_beacon_SOURCES = $(COMMON_SRC) $(BEACON_SRC)
bfdd_beacon_LDADD =  $(INTI_LIBS)
endif

bfdd_beacon_LDFLAGS = -pthread
bfdd_beacon_MANS = bfdd-beacon.8

bfdd_control_SOURCES = $(COMMON_SRC) $(CONTROL_SRC)
bfdd_control_LDADD =  $(INTI_LIBS)
bfdd_control_LDFLAGS = -pthread
bfdd_control_MANS = bfdd-control.8

EXTRA_DIST = $(bfdd_beacon_MANS) $(bfdd_control_MANS) LICENSE
man_MANS = $(bfdd_beacon_MANS) $(bfdd_control_MANS)
