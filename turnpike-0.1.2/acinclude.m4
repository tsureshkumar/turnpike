AC_DEFUN([TPIKE_EXPAND_DIR], 
[
	$1=$2
	$1=`(
		test "x$prefix" = xNONE && prefix="$ac_default_prefix"
                test "x$exec_prefix" = xNONE && exec_prefix="${prefix}"
                eval echo \""[$]$1"\"
            )`
])

dnl  Check if either va_copy() or __va_copy() is available. On linux systems 
dnl  at least one of these should be present.
AC_DEFUN([RACOON_CHECK_VA_COPY], [
	saved_CFLAGS=$CFLAGS
	CFLAGS="-Wall -O2"
	AC_CACHE_CHECK([for an implementation of va_copy()],
		ac_cv_va_copy,[
		AC_TRY_RUN([#include <stdarg.h>
		void func (int i, ...) {
			va_list args1, args2;
			va_start (args1, i);
			va_copy (args2, args1);
			if (va_arg (args1, int) != 1 || va_arg (args2, int) != 1)
				exit (1);
	 		va_end (args1);
			va_end (args2);
		}
		int main() {
			func (0, 1);
			return 0;
		}],
		[ac_cv_va_copy=yes],
		[ac_cv_va_copy=no],
		AC_MSG_WARN(Cross compiling... Unable to test va_copy)
		[ac_cv_va_copy=no])
	])
	if test x$ac_cv_va_copy != xyes; then
		AC_CACHE_CHECK([for an implementation of __va_copy()],
			ac_cv___va_copy,[
			AC_TRY_RUN([#include <stdarg.h>
			void func (int i, ...) {
				va_list args1, args2;
				va_start (args1, i);
				__va_copy (args2, args1);
				if (va_arg (args1, int) != 1 || va_arg (args2, int) != 1)
					exit (1);
				va_end (args1);
				va_end (args2);
			}
			int main() {
				func (0, 1);
				return 0;
			}],
			[ac_cv___va_copy=yes],
			[ac_cv___va_copy=no],
			AC_MSG_WARN(Cross compiling... Unable to test __va_copy)
			[ac_cv___va_copy=no])
		])
	fi

	if test "x$ac_cv_va_copy" = "xyes"; then
		va_copy_func=va_copy
	elif test "x$ac_cv___va_copy" = "xyes"; then
		va_copy_func=__va_copy
	fi

	if test -n "$va_copy_func"; then
		AC_DEFINE_UNQUOTED(VA_COPY,$va_copy_func,
			[A 'va_copy' style function])
	else
		AC_MSG_WARN([Hmm, neither va_copy() nor __va_copy() found.])
		AC_MSG_WARN([Using a generic fallback.])
	fi
	CFLAGS=$saved_CFLAGS
	unset saved_CFLAGS
])
