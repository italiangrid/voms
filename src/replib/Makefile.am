noinst_LTLIBRARIES = librep.la

librep_la_SOURCES = dummy.c
librep_la_LIBADD	= @LTLIBOBJS@

librep_la_CFLAGS = \
	-I$(top_srcdir)/include \
	-I$(srcdir) \
	-I$(srcdir)/include \
	-I$(GLOBUS_LOCATION)/include/$(GLOBUS_FLAVOR_NAME) \
	-I$(top_srcdir)/sslutils 

MAINTAINERCLEANFILES = Makefile.in
