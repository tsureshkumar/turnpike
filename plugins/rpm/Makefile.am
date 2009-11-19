EXTRA_DIST = \
  novell-nortelugins.spec.in

all-local: novell-nortelugins.spec

novell-nortelugins.spec: novell-nortelugins.spec.in Makefile
	rm -f $@.tmp
	sed < $< > $@.tmp \
	-e 's:@-VERSION-@:${VERSION}:'
	mv $@.tmp $@
	sed < $@ >  $@.tmp \
	-e 's:@-PACKAGE_NAME-@:${PACKAGE_NAME}:'
	mv $@.tmp $@
	sed < $@ >  $@.tmp \
	-e 's:@-TURNPIKEDIR-@:${TURNPIKEDIR}:'
	mv $@.tmp $@
	sed < $@ >  $@.tmp \
	-e 's:@-RACOONSRC-@:${RACOONSRC}:'
	mv $@.tmp $@
CLEANFILES = novell-nortelugins.spec

