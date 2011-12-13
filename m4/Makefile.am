EXTRA_DIST = voms.m4

if BUILD_INTERFACES
install-exec-hook:
	$(mkinstalldirs) $(DESTDIR)/$(datadir)/m4
	$(INSTALL_DATA) $(top_srcdir)/m4/voms.m4 $(DESTDIR)/$(datadir)/m4
endif
