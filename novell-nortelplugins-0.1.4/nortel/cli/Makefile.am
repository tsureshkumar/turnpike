INCLUDES        =  $(LIBXML_CFLAGS) -I@TURNPIKEDIR@/include -I$(top_srcdir)/nortel

LDADD           =  $(LIBXML_LIBS)

CLEANFILES      = *~
DISTCLEANFILES  = .deps/*.P

plugin_LTLIBRARIES = libclinortel.la

libclinortel_la_SOURCES = \
			  adminport.c   \
			  helper.c      \
			  helper.h      \
			  hooks.c	\
			  init.c	\
			  nortelcli.h	\
			  phase1.c      \
			  phase1.h      \
			  phase2.c	\
			  phase2.h	\
			  profile.c     \
			  profile.h     \
			  racoon.c      


libclinortel_la_LDFLAGS = -avoid-version -module ../common/libnortelhelper.la
libclinortel_la_LIBADD = ${CRYPTOBJS}

