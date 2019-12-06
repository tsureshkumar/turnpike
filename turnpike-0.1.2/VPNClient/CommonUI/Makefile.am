noinst_LTLIBRARIES = libCommonUI.la

adminsockdir=${localstatedir}/racoon

libCommonUI_la_SOURCES = CommonUI.c plog.c sockInterface.c vpncExtCert.c  
libCommonUI_la_CFLAGS = -DADMINPORTDIR=\"${adminsockdir}\"

LDADD = @LIBXML_LIBS@
INCLUDES = @LIBXML_CFLAGS@ \
		-I${top_srcdir}/VPNClient/include  \
		-I${top_srcdir}/ErrorGenerator/ \
		-I${top_srcdir}/utility/

libCommonUI_la_LDFLAGS =   -version-info 1:0:0 \
			 ../../ErrorGenerator/libErrorHandling.la ../../utility/libgetip.la -export-dynamic -static


