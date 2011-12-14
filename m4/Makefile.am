EXTRA_DIST = voms.m4

if BUILD_INTERFACES
install-exec-hook:
	$(mkinstalldirs) $(DESTDIR)/$(datadir)/aclocal
	$(INSTALL_DATA) $(top_srcdir)/m4/voms.m4 $(DESTDIR)/$(datadir)/aclocal
endif
