AUTOMAKE_OPTIONS = foreign

SUBDIRS = src common-gnome auth-dialog properties po

dbusservicedir = $(sysconfdir)/dbus-1/system.d
dbusservice_DATA = nm-novellvpn-service.conf

nmvpnservicedir = $(sysconfdir)/NetworkManager/VPN
nmvpnservice_in_files = nm-novellvpn-service.name.in
nmvpnservice_DATA = nm-novellvpn-service.name

desktopdir = $(datadir)/applications
desktop_in_files = nm-novellvpn.desktop.in
desktop_DATA = $(desktop_in_files:.desktop.in=.desktop)
@INTLTOOL_DESKTOP_RULE@

icondir = $(datadir)/icons/hicolor/48x48/apps
icon_DATA = gnome-mime-application-x-novellvpn-settings.png

nm-novellvpn-service.name: $(srcdir)/nm-novellvpn-service.name.in
	sed -e 's|[@]LIBEXECDIR[@]|$(libexecdir)|g' $< >$@

EXTRA_DIST = $(nmvpnservice_DATA) \
             $(nmvpnservice_in_files)  \
	     $(dbusservice_DATA)  \
             $(desktop_in_files)  \
             $(icon_DATA)         \
             intltool-extract.in  \
             intltool-merge.in    \
             intltool-update.in

CLEANFILES = $(desktop_DATA) $(nmvpnservice_DATA) *~
DISTCLEANFILES = intltool-extract intltool-merge intltool-update

ACLOCAL_AMFLAGS = -I m4
