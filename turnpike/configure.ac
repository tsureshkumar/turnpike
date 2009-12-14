dnl                                               -*- Autoconf -*-
dnl Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT(turnpike,0.1.2)
AC_CONFIG_SRCDIR([configure.ac])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE

RELEASE=17
AC_SUBST(RELEASE)

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_LIBTOOL
#ALL_LINGUAS=""

CFLAGS_ADD="-g -Wall -Werror -fno-strict-aliasing"

# Checks for header files.
AC_HEADER_DIRENT
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([arpa/inet.h fcntl.h libintl.h netdb.h netinet/in.h stdlib.h string.h sys/ioctl.h sys/socket.h syslog.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_HEADER_TIME

# Checks for libraries.
# FIXME: Replace `main' with a function in `-lcrypto':
AC_CHECK_LIB([utf8conv], [main])
# FIXME: Replace `main' with a function in `-lutf8conv':
AC_CHECK_LIB([crypto], [main], echo crypto)

# Checks for library functions.
AC_FUNC_CLOSEDIR_VOID
AC_PROG_GCC_TRADITIONAL
AC_FUNC_LSTAT
AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK
AC_FUNC_MALLOC
AC_FUNC_SELECT_ARGTYPES
AC_CHECK_FUNCS([bzero gethostbyaddr gethostbyname inet_ntoa memset select socket strerror strstr])


GETTEXT_PACKAGE=$PACKAGE
AC_SUBST(GETTEXT_PACKAGE)
AC_DEFINE_UNQUOTED(GETTEXT_PACKAGE,"$GETTEXT_PACKAGE", [Gettext package])
ALL_LINGUAS=""
AC_PROG_INTLTOOL([0.27.2])
AM_GLIB_GNU_GETTEXT

# check for pluggin load directory
AC_MSG_CHECKING(if --with-plugindir option is specified)
AC_ARG_WITH(plugindir, 
	[  --with-plugindir=DIR      specify where to put the plugins])
AC_MSG_RESULT(${plugindir-default})

if test "${with_plugindir+set}" = "set" && test $with_plugindir != default; then
   	TPIKE_EXPAND_DIR(plugindir, "$with_plugindir")
	AC_DEFINE_UNQUOTED([LIB_LOAD_PATH], "$plugindir", [pluggin destination dir])
	AC_SUBST(LIB_LOAD_PATH)
else
   	TPIKE_EXPAND_DIR(plugindir, "${libdir}/turnpike/plugins")
	AC_DEFINE_UNQUOTED([LIB_LOAD_PATH], "$plugindir", [pluggin destination dir])
	AC_SUBST(LIB_LOAD_PATH)
fi

# Check if a racoonsrc directory was specified
AC_MSG_CHECKING(if --with-racoonsrc option is specified)
AC_ARG_WITH(racoonsrc, [  --with-racoonsrc=DIR      specify ipsec-tools src directory],
	[racoon_dir=$withval])
AC_MSG_RESULT(${racoon_dir-default})

if test "x$racoon_dir" != "x"; then
	LIBS="$LIBS -L${racoon_dir}/lib"
	echo "Adding to CPPFLAGS and CFLAGS"
	CPPFLAGS_ADD="-I${racoon_dir}/src/racoon -I${racoon_dir}/src/libipsec -I${racoon_dir}/src/include-glibc -I${racoon_dir}/src $CPPFLAGS_ADD"
	CFLAGS_ADD="-I${racoon_dir}/src/racoon -I${racoon_dir}/src/libipsec -I${racoon_dir}/src/include-glibc -I${racoon_dir}/src  $CFLAGS_ADD"
	RACOONSRC=$racoon_dir
	AC_DEFINE([RACOONSRC], [], [racoon src])
	AC_SUBST(RACOONSRC)
fi

MINIPSECVER="0.5.1"
AC_MSG_CHECKING(ipsec-tools version) 
IPSECTOOLSVER=`cat ${racoon_dir}/configure.ac | gawk "/\A\C_INIT[(]ipsec-tools, (.*)[)]/ { print $1}"`
if test -n "${IPSECTOOLSVER} >= ${MINIPSECVER}"; then
  AC_MSG_RESULT(ok) ;
else
  AC_MSG_WARN([ipsec-tools version must be  higher. Aborting]);
fi
AC_CHECK_HEADERS(isakmp_var.h)

RACOON_CHECK_VA_COPY

CFLAGS="$CFLAGS $CFLAGS_ADD"
CPPFLAGS="$CPPFLAGS $CPPFLAGS_ADD"

dnl check for gtk
dnl AM_PATH_GTK_2_0(2.2.0,,AC_MSG_ERROR(nortelplugin 0.1 needs GTK+ 2.2.0 or greater))
PKG_CHECK_MODULES(GTK, gtk+-2.0 >= 2.6)
AC_SUBST(GTK_CFLAGS)
AC_SUBST(GTK_LIBS)

dnl check for libxml
LIBXML_REQUIRED_VERSION=2.6.0
PKG_CHECK_MODULES(BASE_DEPENDENCIES, libxml-2.0 >= $LIBXML_REQUIRED_VERSION)
LIBXML_CFLAGS=`$PKG_CONFIG --cflags libxml-2.0`
LIBXML_LIBS=`$PKG_CONFIG --libs libxml-2.0`
AC_SUBST(LIBXML_CFLAGS)
AC_SUBST(LIBXML_LIBS)


include_turnpikedir=${includedir}/turnpike
AC_SUBST(include_turnpikedir)

AC_CONFIG_FILES([
		Makefile
		package_version.h
		ErrorGenerator/Makefile
                utility/Makefile
		VPNClient/Makefile
		VPNClient/CommonUI/Makefile
		VPNClient/vpnc/Makefile
		VPNClient/vpnc/src/Makefile
		VPNClient/vpnlogin/Makefile
		VPNClient/vpnlogin/src/Makefile
                rpm/turnpike.spec
                po/Makefile.in
                 ])
AC_OUTPUT
