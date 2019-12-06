SUBDIRS=nortel

EXTRA_DIST = ipalias dnsupdate include-fix

rpm:
	make dist
	cp ${PACKAGE}-${VERSION}.tar.gz /usr/src/packages/SOURCES/
	rpmbuild -bb rpm/${PACKAGE}.spec

.PHONY: rpm
