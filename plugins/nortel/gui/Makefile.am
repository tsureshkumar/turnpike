INCLUDES        = @GTK_CFLAGS@ \
		  $(LIBXML_CFLAGS) \
		  -I$(top_srcdir)/nortel

LDADD           = @GTK_LIBS@ \
		  $(LIBXML_LIBS)

CLEANFILES      = *~
DISTCLEANFILES  = .deps/*.P

plugin_LTLIBRARIES = libguinortel.la

libguinortel_la_SOURCES = \
			  adminport.c 		\
			  adminport.h 		\
			  authframe.c 		\
			  authframe.h 		\
			  connection.c 		\
			  entrypoint.c		\
			  hooks.c 		\
			  hooks.h     		\
			  phase1.c 		\
			  phase1.h		\
			  phase2.c		\
			  phase2.h		\
			  profile.c 		\
			  racoon.c 		


libguinortel_la_LDFLAGS = -avoid-version -module ../common/libnortelhelper.la

libguinortel_ladir = $(libdir)
libguinortel_la_LIBADD = ${CRYPTOBJS}
