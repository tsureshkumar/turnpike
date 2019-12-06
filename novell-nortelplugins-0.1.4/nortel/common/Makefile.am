INCLUDES        =  $(LIBXML_CFLAGS)

LDADD           =  $(LIBXML_LIBS)

CLEANFILES      = *~
DISTCLEANFILES  = .deps/*.P

plugin_LTLIBRARIES = libnortelhelper.la

libnortelhelper_la_SOURCES = \
			     encrypt.c 		\
			     helper.c  		\
			     helper.h 		\
			     norteladmin.c	\
			     plog.h		\
			     profile.c		\
			     profile.h 		\
		  	     encrypt.h 		\
		  	     norteladmin.h	

libnortelhelper_la_CFLAGS = -fPIC
libnortelhelper_la_LDFLAGS = -static
