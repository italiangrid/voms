JAVAC=$(JHOME)/bin/javac
JAR=$(JHOME)/bin/jar

JAVA_CLASSES = org/glite/voms/BasicVOMSTrustStore.class \
							 org/glite/voms/FQAN.class \
							 org/glite/voms/LSCFile.class \
							 org/glite/voms/SigningPolicy.class \
							 org/glite/voms/PKIStore.class \
							 org/glite/voms/PKIUtils.class \
							 org/glite/voms/PKIVerifier.class \
							 org/glite/voms/SigningPolicy.class \
							 org/glite/voms/VOMSAttribute.class \
							 org/glite/voms/VOMSValidator.class \
							 org/glite/voms/VOMSTrustManager.class \
							 org/glite/voms/VOMSKeyManager.class \
							 org/glite/voms/ac/ACGenerator.class \
							 org/glite/voms/ac/ACTrustStore.class \
							 org/glite/voms/ac/ACValidator.class \
							 org/glite/voms/ac/AttCertIssuer.class \
							 org/glite/voms/ac/AttributeCertificateInfo.class \
							 org/glite/voms/ac/AttributeCertificate.class \
							 org/glite/voms/ac/Holder.class \
							 org/glite/voms/ac/IetfAttrSyntax.class \
							 org/glite/voms/ac/ObjectDigestInfo.class \
							 org/glite/voms/ac/Util.class \
							 org/glite/voms/ac/ACTarget.class \
							 org/glite/voms/ac/ACTargets.class \
							 org/glite/voms/ac/ACCerts.class \
							 org/glite/voms/ac/GenericAttribute.class \
							 org/glite/voms/ac/AttributeHolder.class \
							 org/glite/voms/ac/FullAttributes.class \
							 org/glite/voms/ac/VOMSTrustStore.class \
							 org/glite/voms/contact/cli/VomsProxyInitClient.class \
							 org/glite/voms/contact/PathNamingScheme.class \
							 org/glite/voms/contact/Test.class \
							 org/glite/voms/contact/UserCredentials.class \
							 org/glite/voms/contact/VOMSDecoder.class \
							 org/glite/voms/contact/VOMSErrorMessage.class \
							 org/glite/voms/contact/VOMSESFileParser.class \
							 org/glite/voms/contact/VOMSException.class \
							 org/glite/voms/contact/VOMSParser.class \
							 org/glite/voms/contact/VOMSProtocol.class \
							 org/glite/voms/contact/VOMSProxyBuilder.class \
							 org/glite/voms/contact/VOMSProxyInit.class \
							 org/glite/voms/contact/VOMSRequestFactory.class \
							 org/glite/voms/contact/VOMSRequestOptions.class \
							 org/glite/voms/contact/VOMSResponse.class \
							 org/glite/voms/contact/VOMSServerInfo.class \
							 org/glite/voms/contact/VOMSServerMap.class \
							 org/glite/voms/contact/VOMSSocket.class \
							 org/glite/voms/contact/MyProxyCertInfo.class \
							 org/glite/voms/contact/ProxyPolicy.class \
							 org/glite/voms/contact/VOMSProxyConstants.class \
							 org/glite/voms/contact/VOMSSyntaxException.class


all-local: $(top_builddir)/src/api/java/vomsjapi.jar

%.class : %.java
	$(JAVAC) -sourcepath $(top_srcdir)/src/api/java -classpath $(JAVA_CLASSPATH):$(JAVA_CLASSPATH2):$(CLASSPATH) -d $(top_builddir)/src/api/java $<

$(top_builddir)/src/api/java/vomsjapi.jar: makedirs $(JAVA_CLASSES)
	$(JAR) -cfm $(top_builddir)/src/api/java/vomsjapi.jar $(top_srcdir)/src/api/java/Manifest.add `find org -name '*.class'` $(top_srcdir)/src/api/java/log4j.properties ;

makedirs:
	mkdir -p $(top_builddir)/src/api/java/org/glite/voms/ac

install-exec-hook:
	$(mkinstalldirs) $(DESTDIR)/$(datadir)/java
	$(INSTALL) $(top_builddir)/src/api/java/vomsjapi.jar $(DESTDIR)/$(datadir)/java

clean:
	rm -f $(top_builddir)/src/api/java/vomsapi.jar
	find $(top_builddir)/src/api/java -name '*.class' -exec rm -f '{}' ';'

#java_JAVA =  privateinternal.java
