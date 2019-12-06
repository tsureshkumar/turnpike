#! /bin/sh -x 
#
# racoon - start/stop racoon from a script.
# used to detect whether racoon is running or not.
#
# Sureshkumar T 

case "$1" in
	up)
		ps -C racoon -o pid= &>/dev/null && exit 2
		test -f /etc/init.d/racoond && /etc/init.d/racoond start
		;;
	down)
		ps -C racoon -o pid= &>/dev/null || exit 2
		test -f /etc/init.d/racoond && /etc/init.d/racoond stop
		exit 0
		;;
	*)
		exit 0
		;;
esac
