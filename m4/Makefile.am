EXTRA_DIST = voms.m4

if BUILD_INTERFACES
install-exec-hook:
	$(mkinstalldirs) $(DESTDIR)$(datadir)/aclocal
	$(INSTALL_DATA) $(top_srcdir)/m4/voms.m4 $(DESTDIR)$(datadir)/aclocal

uninstall-hook:
	rm -f $(DESTDIR)$(datadir)/aclocal/voms.m4
	rmdir $(DESTDIR)$(datadir)/aclocal 2>/dev/null || true
endif
