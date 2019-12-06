plugin_LTLIBRARIES = libnortel.la

# for header files
INCLUDES = -DENABLE_ADMINPORT -I$(top_srcdir)/nortel \
		@INCLUDE_FIX@

libnortel_la_SOURCES = \
			$(top_srcdir)/nortel/common/encrypt.c \
			$(top_srcdir)/nortel/common/encrypt.h \
			attrcheck.c		\
			attrgen.c		\
			attrgen.h		\
			callbacks.c		\
			callbacks.h		\
			fwinterface.c		\
			nortel_inf.h		\
			nortel_inf.c		\
			nortel_vmbuf.c		\
			nortel_vmbuf.h		\
			packets.c		\
			packets.h		\
			payloadcheck.c		\
			payloadgen.c		\
			payloadgen.h		\
			registerattr.c		\
			registerattr.h		\
			registerpayload.c	\
			registerpayload.h	\
			nortel_cfg.h		\
			nortel_cfg.c		\
			nortel_nat.h		\
			nortel_nat.c		\
			utility.c		\
			utility.h

libnortel_la_LDFLAGS = -avoid-version -module
libnortel_la_LIBADD = $(CRYPTOBJS)

plugin_SCRIPTS=$(top_srcdir)/ipalias $(top_srcdir)/dnsupdate

