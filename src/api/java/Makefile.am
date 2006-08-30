JAVAC=$(JHOME)/bin/javac
JAR=$(JHOME)/bin/jar

JAVA_CLASSES = org/glite/security/voms/BasicVOMSTrustStore.class \
							 org/glite/security/voms/FQAN.class \
							 org/glite/security/voms/LSCFile.class \
							 org/glite/security/voms/SigningPolicy.class \
							 org/glite/security/voms/PKIStore.class \
							 org/glite/security/voms/PKIUtils.class \
							 org/glite/security/voms/PKIVerifier.class \
							 org/glite/security/voms/SigningPolicy.class \
							 org/glite/security/voms/VOMSAttribute.class \
							 org/glite/security/voms/VOMSValidator.class \
							 org/glite/security/voms/ac/ACGenerator.class \
							 org/glite/security/voms/ac/ACTrustStore.class \
							 org/glite/security/voms/ac/ACValidator.class \
							 org/glite/security/voms/ac/AttCertIssuer.class \
							 org/glite/security/voms/ac/AttributeCertificateInfo.class \
							 org/glite/security/voms/ac/AttributeCertificate.class \
							 org/glite/security/voms/ac/Holder.class \
							 org/glite/security/voms/ac/IetfAttrSyntax.class \
							 org/glite/security/voms/ac/ObjectDigestInfo.class \
							 org/glite/security/voms/ac/Util.class \
							 org/glite/security/voms/ac/ACTarget.class \
							 org/glite/security/voms/ac/ACTargets.class \
							 org/glite/security/voms/ac/ACCerts.class \
							 org/glite/security/voms/ac/GenericAttribute.class \
							 org/glite/security/voms/ac/AttributeHolder.class \
							 org/glite/security/voms/ac/FullAttributes.class \
							 org/glite/security/voms/ac/VOMSTrustStore.class

all-local: $(top_builddir)/src/api/java/vomsjapi.jar

%.class : %.java
	$(JAVAC) -sourcepath $(top_srcdir)/src/api/java -classpath $(JAVA_CLASSPATH):$(CLASSPATH) -d $(top_builddir)/src/api/java $<

$(top_builddir)/src/api/java/vomsjapi.jar: makedirs $(JAVA_CLASSES)
	$(JAR) -cf $(top_builddir)/src/api/java/vomsjapi.jar `find org -name '*.class'` ;

makedirs:
	mkdir -p $(top_builddir)/src/api/java/org/glite/security/voms/peers
	mkdir -p $(top_builddir)/src/api/java/org/glite/security/voms/ac

install-exec-hook:
	$(mkinstalldirs) $(DESTDIR)/$(datadir)/java
	$(INSTALL) $(top_builddir)/src/api/java/vomsjapi.jar $(DESTDIR)/$(datadir)/java

clean:
	rm -f $(top_builddir)/src/api/java/vomsapi.jar
	find $(top_builddir)/src/api/java -name '*.class' -exec rm -f '{}' ';'

#java_JAVA =  privateinternal.java
