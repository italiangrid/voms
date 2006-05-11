JAVAC=$(JHOME)/bin/javac
JAR=$(JHOME)/bin/jar
JAVAH=$(JHOME)/bin/javah

JAVA_CLASSES = org/glite/security/voms/peers/VomsdataPeer.class \
							 org/glite/security/voms/peers/ContactDataPeer.class \
							 org/glite/security/voms/peers/VomsPeer.class \
							 org/glite/security/voms/peers/DataPeer.class \
							 org/glite/security/voms/peers/AttributePeer.class \
						   org/glite/security/voms/peers/AttributeListPeer.class \
							 org/glite/security/voms/BasicVOMSTrustStore.class \
							 org/glite/security/voms/FQAN.class \
							 org/glite/security/voms/VOMSAttribute.class \
							 org/glite/security/voms/VOMSValidator.class \
							 org/glite/security/voms/AttributeList.class \
							 org/glite/security/voms/Attribute.class \
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
							 org/glite/security/voms/ac/V2Form.class
all-local: $(top_builddir)/src/api/java/vomsjapi.jar

%.class : %.java
	$(JAVAC) -sourcepath . -classpath $(JAVA_CLASSPATH):$(CLASSPATH) -d $(top_builddir)/src/api/java $<

$(top_builddir)/src/api/java/vomsjapi.jar: makedirs $(JAVA_CLASSES)
	TMPDIR=`pwd` \
	cd $(top_builddir)/src/api/java \
	$(JAR) -cf $(top_builddir)/src/api/java/vomsjapi.jar `find org -name '*.class'` \
	cd $(TMPDIR)
	$(JAVAH) -classpath $(top_builddir)/src/api/java:$(JAVA_CLASSPATH):$(CLASSPATH) -o ../ccapi/jni-int.h org.glite.security.voms.peers.VomsdataPeer org.glite.security.voms.peers.ContactDataPeer org.glite.security.voms.peers.VomsPeer org.glite.security.voms.peers.DataPeer org.glite.security.voms.peers.AttributePeer org.glite.security.voms.peers.AttributeListPeer

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
