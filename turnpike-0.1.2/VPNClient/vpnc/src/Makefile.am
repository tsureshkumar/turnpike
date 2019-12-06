LDADD           =  $(LIBXML_LIBS) $(INTLLIBS) -lcrypto

INCLUDES =-DPACKAGE_DATA_DIR=\""$(datadir)"\" \
	-DLOCALE_DIR=\""$(prefix)/$(DATADIRNAME)/locale"\" \
	-DGETTEXT_PACKAGE=\""$(GETTEXT_PACKAGE)"\" \
	$(LIBXML_CFLAGS)

INCLUDES += -I. -I${top_srcdir}/VPNClient/vpnc/include -I${top_srcdir}/VPNClient/include -I${top_srcdir}/ErrorGenerator -I${top_srcdir}/utility

bin_PROGRAMS = nvpn
include_turnpike_HEADERS=${top_srcdir}/VPNClient/include/commoncli.h ${top_srcdir}/VPNClient/include/racoonconf.h

adminsockdir=${localstatedir}/racoon

nvpn_SOURCES = \
	cli.c  \
	commandHandler.c \
	utility.c \
	profile.c \
	adminPortInterface.c

nvpn_CFLAGS = -DADMINPORTDIR=\"${adminsockdir}\"

#noinst_HEADERS = 

nvpn_LDFLAGS = ../../../ErrorGenerator/libErrorHandling.la ../../../utility/libgetip.la ../../CommonUI/libCommonUI.la

