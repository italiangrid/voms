
sbin_PROGRAMS = voms

voms_SOURCES = \
	access_db_sql.cc \
	access_db_sql.h \
	main.cc \
	vomsd.cc \
	VOMSServer.h \
	attribute.h \
	attribute.cc

voms_LDADD = \
	$(top_builddir)/src/api/ccapi/libvomsapi.la \
	$(EXPAT_LIBS)

# voms_LDADD = \
# 	$(top_builddir)/src/socklib/libsock.la \
# 	$(top_builddir)/src/common/libutilities.la \
# 	$(top_builddir)/src/sslutils/libssl_utils.la \
# 	$(top_builddir)/src/ac/libccattcert.la \
# 	$(top_builddir)/src/common/libutilc.la \
# 	$(top_builddir)/src/ac/libattcert.la \
# 	$(top_builddir)/src/replib/librep.la \
# 	$(top_builddir)/src/log/liblog.la \
# 	$(top_builddir)/src/api/ccapi/libvomsapi.la \
# 	$(EXPAT_LIBS)

if LINK_FULL_TABLE
voms_LDFLAGS = -Wl,-E
endif

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/include \
	-I$(top_srcdir)/src/api/ccapi \
	$(GLOBUS_CFLAGS)

install-exec-hook:
	-ln -s voms $(DESTDIR)$(sbindir)/edg-voms
if ENABLE_GLITE
	-ln -s voms $(DESTDIR)$(sbindir)/glite-voms
endif
