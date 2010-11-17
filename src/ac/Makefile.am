
noinst_LTLIBRARIES = \
  libattributes_nog.la

AC_C_SOURCES = write.c extensions.c mystack.c error.c newformat.c init.c

AC_CC_SOURCES = validate.cc create.cc ccinit.cc

EXTRA_DIST = \
	acerrors.h \
	write.h \
	init.h \
	extensions.h \
	attributes.h

libattributes_nog_la_SOURCES = $(AC_C_SOURCES) $(AC_CC_SOURCES)

libattributes_nog_la_CFLAGS = \
	$(NO_GLOBUS_FLAGS) \
	-DNOGLOBUS \
	-I $(top_srcdir)/src/include \
	-I $(top_builddir)/src/sslutils

libattributes_nog_la_CXXFLAGS = \
	$(NO_GLOBUS_FLAGS) \
	-DNOGLOBUS \
	-I $(top_srcdir)/src/include \
	-I $(top_builddir)/src/sslutils

libattributes_nog_la_LIBADD = \
	$(OPENSSL_LIBS)

AM_CPPFLAGS= \
	-I $(top_srcdir)/src/include \
	-I $(top_srcdir)/src/sslutils

###
