/*********************************************************************
 *
 * Authors: Vincenzo Ciaschini - Vincenzo.Ciaschini@cnaf.infn.it
 *
 * Copyright (c) Members of the EGEE Collaboration. 2004-2010.
 * See http://www.eu-egee.org/partners/ for details on the copyright holders.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Parts of this code may be based upon or even include verbatim pieces,
 * originally written by other people, in which case the original header
 * follows.
 *
 *********************************************************************/

package org.glite.voms;

import java.io.IOException;
import java.io.InputStream;
import java.io.ByteArrayInputStream;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.Stack;
import java.util.TreeSet;
import java.util.HashSet;
import java.util.Vector;

import javax.security.auth.x500.X500Principal;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.glite.voms.ac.ACCerts;
import org.glite.voms.ac.ACTargets;
import org.glite.voms.ac.AttributeCertificate;
import org.glite.voms.ac.AttributeCertificateInfo;
import org.glite.voms.ac.VOMSTrustStore;
import org.glite.voms.contact.MyProxyCertInfo;

class MyDERInputStream extends ASN1InputStream {
    public MyDERInputStream(InputStream is) {
        super(is);
    }

    public int readLength() throws IOException {
        return super.readLength();
    }
}

public class PKIVerifier {

    private static Logger logger = Logger.getLogger( PKIVerifier.class
            .getName() );

    public static final String SUBJECT_KEY_IDENTIFIER = "2.5.29.14";

    public static final String AUTHORITY_KEY_IDENTIFIER = "2.5.29.35";

    public static final String PROXYCERTINFO = "1.3.6.1.5.5.7.1.14";

    public static final String PROXYCERTINFO_OLD = "1.3.6.1.4.1.3536.1.222";

    public static final String BASIC_CONSTRAINTS_IDENTIFIER = "2.5.29.19";

    public static final String KEY_USAGE_IDENTIFIER = "2.5.29.15";

    public static final String TARGET = "2.5.29.55";

    private static final String[] OIDs = { SUBJECT_KEY_IDENTIFIER,
            AUTHORITY_KEY_IDENTIFIER, PROXYCERTINFO, PROXYCERTINFO_OLD,
            BASIC_CONSTRAINTS_IDENTIFIER, KEY_USAGE_IDENTIFIER };

    private static final String[] AC_OIDs = { TARGET };

    private static final Set handledOIDs = new TreeSet( Arrays.asList( OIDs ) );

    private static final Set handledACOIDs = new TreeSet( Arrays
            .asList( AC_OIDs ) );

    private PKIStore caStore = null;

    private VOMSTrustStore vomsStore = null;

    static {
        if ( Security.getProvider( "BC" ) == null ) {
            Security.addProvider( new BouncyCastleProvider() );
        }
    }

    /**
     * Initializes the verifier.
     * 
     * @param vomsStore
     *            the VOMSTrustStore object which represents the vomsdir store.
     * @param caStore
     *            the PKIStore object which represents the CA store.
     */
    public PKIVerifier( VOMSTrustStore vomsStore, PKIStore caStore ) {

        this.vomsStore = vomsStore;
        this.caStore = caStore;
    }

    /**
     * Initializes the verifier. The CA store is initialized at:
     * "/etc/grid-security/certificates."
     * 
     * @param vomsStore
     *            the VOMSTrustStore object which represents the vomsdir store.
     * 
     * @throws IOException
     *             if there have been IO errors.
     * @throws CertificateException
     *             if there have been problems parsing a certificate
     * @throws CRLException
     *             if there have been problems parsing a CRL.
     */
    public PKIVerifier( VOMSTrustStore vomsStore ) throws IOException,
            CertificateException, CRLException {
        this.vomsStore = vomsStore;

        this.caStore = PKIStoreFactory.getStore(PKIStore.TYPE_CADIR);
    }

    /**
     * Initializes the verifier. 
     * 
     * If the VOMSDIR and CADIR system properties are set, those values
     * are used to initialize the voms and ca certificates trust stores.
     * Tipically, the VOMSDIR should point to a directory that contains
     * voms server certificates, while the CADIR should point to a 
     * directory where CA certificates and crl are stored.
     * 
     * If the system properties are not set, The CA store is initialized to:
     * "/etc/grid-security/certificates.", while the VOMS store is initialized
     * to "/etc/grid-security/vomsdir" (slash becomes backslash on windows).
     * 
     * @throws IOException
     *             if there have been IO errors.
     * @throws CertificateException
     *             if there have been problems parsing a certificate
     * @throws CRLException
     *             if there have been problems parsing a CRL.
     */
    public PKIVerifier() throws IOException, CertificateException, CRLException {

        vomsStore = PKIStoreFactory.getStore(PKIStore.TYPE_VOMSDIR);
        caStore   = PKIStoreFactory.getStore(PKIStore.TYPE_CADIR);
    }

    /**
     * Cleans up resources allocated by the verifier.
     * 
     * This method MUST be called prior to disposal of this object, otherwise
     * memory leaks and runaway threads will occur.
     */
    public void cleanup() {

        if ( vomsStore != null )
            vomsStore.stopRefresh();

        if ( caStore != null )
            caStore.stopRefresh();

        vomsStore = null;
        caStore = null;
    }

    /**
     * Sets a new CAStore.
     * 
     * @param store
     *            the new CA store.
     */
    public void setCAStore( PKIStore store ) {

        if ( caStore != null ) {
            caStore.stopRefresh();
            caStore = null;
        }
        caStore = store;
    }

    /**
     * Sets a new VOMSStore.
     * 
     * @param store
     *            the new VOMS store.
     */
    public void setVOMSStore( VOMSTrustStore store ) {

        if ( vomsStore != null ) {
            vomsStore.stopRefresh();
            vomsStore = null;
        }
        vomsStore = store;
    }

    private static String getHostName() {

        try {
            InetAddress addr = InetAddress.getLocalHost();
            return addr.getCanonicalHostName();
        } catch ( UnknownHostException e ) {
            logger.error( "Cannot discover hostName." );
            return "";
        }
    }

    /**
     * Verifies an Attribute Certificate according to RFC 3281.
     * 
     * @param ac
     *            the Attribute Certificate to verify.
     * 
     * @return true if the attribute certificate is verified, false otherwise.
     */
    public boolean verify( AttributeCertificate ac ) {

        if ( ac == null || vomsStore == null )
            return false;

        AttributeCertificateInfo aci = ac.getAcinfo();
        X509Certificate[] certificates = null;

        ACCerts certList = aci.getCertList();

        LSCFile lsc = null;
        String voName = ac.getVO();

        if ( certList != null )
            lsc = vomsStore.getLSC( voName, ac.getHost() );

        logger.debug("LSC is: " + lsc);
        if ( lsc != null ) {
            boolean success = false;
            Vector dns = lsc.getDNLists();
            Iterator dnIter =dns.iterator();

            // First verify if LSC file applies;

            while ( !success && dnIter.hasNext()) {
                boolean doBreak = false;

                while (dnIter.hasNext() && !doBreak ) {
                    Iterator certIter = certList.getCerts().iterator();
                    Vector realDNs = (Vector) dnIter.next();
                    Iterator realDNsIter = realDNs.iterator();

                    while (realDNsIter.hasNext() && certIter.hasNext() && !doBreak ) {
                        String dn = null;
                        String is = null;

                        try {
                            dn = (String) realDNsIter.next();
                            is = (String) realDNsIter.next();
                        } catch ( NoSuchElementException e ) {
                            doBreak = true;
                        }
                        X509Certificate cert = (X509Certificate) certIter.next();
                        String candidateDN = PKIUtils
                            .getOpenSSLFormatPrincipal( cert.getSubjectDN() );
                        String candidateIs = PKIUtils
                            .getOpenSSLFormatPrincipal( cert.getIssuerDN() );

                        logger.debug("canddn is : " + candidateDN);
                        logger.debug("candis is : " + candidateIs);

                        if (dn != null) {
                            logger.debug("dn is : " + dn);
                            logger.debug("dn == canddn is " + dn.equals(candidateDN));
                        }

                        if (is != null) {
                            logger.debug("is is : " + is);
                            logger.debug("is == candis is " + is.equals(candidateIs));
                        }

                        if ( dn != null && is != null)
                            if (!dn.equals(candidateDN) || !is.equals(candidateIs))
                                doBreak = true;
                    }

                    if ( !doBreak && !realDNsIter.hasNext() && !certIter.hasNext() )
                        success = true;
                }
            }

            if ( success == true ) {
                // LSC found. Now verifying certificate
                logger.debug("LSC Verification step.");
                certificates = (X509Certificate[]) certList.getCerts().toArray(
                        new X509Certificate[] {} );
                if (!ac.verifyCert(certificates[0])) {
                    certificates = null;
                    logger.debug( "Signature Verification false (from LSC)." );
                }
                else {
                    logger.debug( "Signature Verification OK (from LSC)." );
                }
            }
        }

        if ( certificates == null ) {
            // lsc check failed
            logger.debug("lsc check failed.");

            if ( logger.isDebugEnabled() ) {
                X500Principal issuer = ac.getIssuer();
                logger.debug( "Looking for hash: "
                        + PKIUtils.getHash(issuer)
                        + " for certificate: " + issuer.getName() );
            }

            X509Certificate[] candidates = vomsStore.getAACandidate( ac
                    .getIssuer(), voName );

            if (candidates == null)
                logger.debug("No candidates found!");
            else if ( candidates.length != 0 ) {
                int i = 0;
                while ( i < candidates.length ) {
                    X509Certificate currentCert = (X509Certificate) candidates[i];
                    PublicKey key = currentCert.getPublicKey();

                    if ( logger.isDebugEnabled() ) {
                        logger.debug( "Candidate: "
                                + currentCert.getSubjectDN().getName() );
                        logger.debug( "Key class: " + key.getClass() );
                        logger.debug( "Key: " + key );
                        byte[] data = key.getEncoded();
                        StringBuffer str = new StringBuffer();
                        str.append("Key: ");

                        for ( int j = 0; j < data.length; j++ ) {
                            str.append(Integer.toHexString( data[j] ));
                            str.append(' ');
                        }

                        logger.debug(str.toString());
                    }

                    if ( ac.verifyCert( currentCert ) ) {
                        logger.debug( "Signature Verification OK" );

                        certificates = new X509Certificate[1];
                        certificates[0] = currentCert;
                        break;
                    } else {
                        logger.debug( "Signature Verification false" );
                    }
                    i++;
                }
            }
        }

        if ( certificates == null ) {
            logger.error( "Cannot find usable certificates to validate the AC. Check that the voms server host certificate is in your vomsdir directory." );
            return false;
        }

        if ( logger.isDebugEnabled() ) {
            for ( int l = 0; l < certificates.length; l++ )
                logger.debug( "Position: " + l + " value: "
                        + certificates[l].getSubjectDN().getName() );
        }

        if ( !verify( certificates ) ) {
            logger.error( "Cannot verify issuer certificate chain for AC" );
            return false;
        }

        if ( !ac.isValid() ) {
            logger.error( "Attribute Certificate not valid at current time." );
            return false;
        }

        // AC Targeting verification

        ACTargets targets = aci.getTargets();

        if ( targets != null ) {
            String hostname = getHostName();

            boolean success = false;
            Iterator i = targets.getTargets().iterator();

            while ( i.hasNext() ) {
                String name = (String) i.next();

                if ( name.equals( hostname ) ) {
                    success = true;
                    break;
                }
            }
            if ( !success ) {
                logger.error( "Targeting check failed!" );
                return false;
            }
        }

        // unhandled extensions check
        X509Extensions exts = aci.getExtensions();

        if ( exts != null ) {
            Enumeration oids = exts.oids();
            while ( oids.hasMoreElements() ) {
                DERObjectIdentifier oid = (DERObjectIdentifier) oids
                        .nextElement();
                X509Extension ext = exts.getExtension( oid );
                if ( ext.isCritical() && !handledACOIDs.contains( oid ) ) {
                    logger.error( "Unknown critical extension discovered: "
                            + oid.getId() );
                    return false;
                }
            }
        }
        return true;
    }

    private boolean checkProxyCertInfo(X509Certificate cert, int posInChain, int chainSize) {
        X509Extension ext = null;
        byte[] payload = cert.getExtensionValue(PROXYCERTINFO);
        if (payload == null) {
            payload = cert.getExtensionValue(PROXYCERTINFO_OLD);
            if (payload == null) {
                logger.debug("No ProxyCertInfo extension found.");
                return true;
            }
            else {
                ext = new X509Extension(false, new DEROctetString(payload));
            }
        }
        else
            ext = new X509Extension(true, new DEROctetString(payload));

        DERObject obj = null;

        try {
            obj = new ASN1InputStream(new ByteArrayInputStream(ext.getValue().getOctets())).readObject();
            MyDERInputStream str = new MyDERInputStream(((DEROctetString)obj).getOctetStream());
            int len = 0;
            int res = 0;
            str.read();
            len = str.readLength();
            res  = str.read(payload, 0, len);
        }
        catch (IOException e) {
            throw new IllegalArgumentException("Cannot read DERObject from source data:"+ e.getMessage());
        }

        MyProxyCertInfo pci = new MyProxyCertInfo(payload);

        logger.info("Constraint: " + pci.getPathLenConstraint() + 
                    "   Size: " + chainSize + "   Current: " + posInChain);
        if (pci.getPathLenConstraint() != -1 && (pci.getPathLenConstraint() < chainSize - posInChain)) {
            return false;
        }

        return true;
    }

    /**
     * Verifies an certificate chain according to RFC 3280.
     * 
     * @param certs
     *            the chain to verify.
     * 
     * @return true if the chain is verified, false otherwise.
     */
    public boolean verify( X509Certificate[] certs ) {

        if ( caStore == null ) {
            logger.error( "No Trust Anchor are known." );
            return false;
        }

        if ( certs.length <= 0 ) {
            logger
                    .error( "Certificate verification: passed empty certificate array." );
            return false;
        }

        Hashtable certificates = caStore.getCAs();

        Stack certStack = new Stack();

        int proxyCount = 0;

        // First, build the certification path
        certStack.push( certs[0] );

        logger.info( "Certificate verification: Verifying certificate '"
                + certs[0].getSubjectDN().getName() + "'" );

        X509Certificate currentCert = certs[0];

        logger.debug( "path length = " + certs.length );

        for ( int i = 1; i < certs.length; i++ ) {
            if ( logger.isDebugEnabled() )
                logger.debug( "Checking: " + certs[i].getSubjectDN().getName() );

            if ( PKIUtils.checkIssued( certs[i], certs[i - 1] ) ) {

                logger.debug( "Is issuer" );

                if (PKIUtils.isProxy(currentCert)) {
                    logger.debug("Increase proxycount");
                    proxyCount ++;
                }

                certStack.push( certs[i] );
                currentCert = certs[i];

                if ( logger.isDebugEnabled() )
                    logger.debug( "ELEMENT: "
                            + currentCert.getSubjectDN().getName() );
            }
            logger.debug( "Is not issuer" );
        }

        logger.debug( "Before anchor searching." );
        X509Certificate candidate = null;

        if ( logger.isDebugEnabled() ) {
            Iterator j = certStack.iterator();
            while ( j.hasNext() )
                logger.debug( "Content: "
                        + ( (X509Certificate) j.next() ).getSubjectDN()
                                .getName() );
        }

        // replace self-signed certificate passed with one from store.
        if ( PKIUtils.selfIssued( currentCert ) ) {
            String hash = PKIUtils.getHash( currentCert );
            Vector candidates = (Vector) certificates.get( hash );
            int index = -1;
            if ( candidates != null
                    && ( index = candidates.indexOf( currentCert ) ) != -1 ) {
                certStack.pop();
                candidate = (X509Certificate) candidates.elementAt( index );
                certStack.push( candidate );

                if ( logger.isDebugEnabled() )
                    logger.debug( "ELEMENT: "
                            + candidate.getSubjectDN().getName() );
            } else {
                logger.error("Cannot find issuer candidate for: " +currentCert.getSubjectDN().getName());
                return false;
            }
        } else {
            candidate = null;

            logger.debug( "Looking for anchor" );
            // now, complete the certification path.
            do {
                String hash = PKIUtils.getHash( currentCert
                        .getIssuerX500Principal() );

                logger.debug( "hash = " + hash );
                Vector candidates = (Vector) certificates.get( hash );
                if ( candidates != null ) {

                    logger.debug( "CANDIDATES: " + candidates );
                    Iterator i = candidates.iterator();
                    while ( i.hasNext() ) {
                        candidate = (X509Certificate) i.next();

                        if ( logger.isDebugEnabled() )
                            logger.debug( "Candidate = "
                                    + candidate.getSubjectDN().getName() );

                        if ( PKIUtils.checkIssued( candidate, currentCert ) ) {
                            certStack.push( candidate );
                            currentCert = candidate;

//                             if (PKIUtils.isProxy(candidate))
//                                 proxyCount ++;

                            if ( logger.isDebugEnabled() )
                                logger.debug( "ELEMENT: "
                                        + candidate.getSubjectDN().getName() );

                            break;
                        } else
                            candidate = null;
                    }
                }
            } while ( candidate != null && !PKIUtils.selfIssued( currentCert ) );
        }

        // no trust anchor found
        if ( candidate == null ) {
            logger.error( "Certificate verification: no trust anchor found." );
            return false;
        }

        int currentLength = 0;
        boolean success = true;

        PublicKey candidatePublicKey = null;
        X509Certificate issuerCert = null;

        if ( logger.isDebugEnabled() ) {
            logger.debug( "Constructed chain:" );

            Iterator j = certStack.iterator();
            while ( j.hasNext() )
                logger.debug( "Content: "
                        + ( (X509Certificate) j.next() ).getSubjectDN()
                                .getName() );
        }

        // now verifies it
        int stackSize = certStack.size();
        int stackPos = stackSize+1;
        Stack constructedStack = new Stack();
        int certCount = 0;

        while ( !certStack.isEmpty() ) {
            currentCert = (X509Certificate) certStack.pop();
            stackPos = stackPos -1;

            if (!PKIUtils.isProxy(currentCert))
                certCount ++;

            if ( logger.isDebugEnabled() )
                logger.debug( "VERIFYING : "
                        + currentCert.getSubjectDN().getName() );

            if (!checkProxyCertInfo(currentCert, stackPos, stackSize)) {
                logger.error("ProxyCertInfo extension violated.");
                return false;
            }
            if ( PKIUtils.selfIssued( currentCert ) ) {
                if ( currentLength != 0 ) {
                    logger
                            .error( "Certificate verification: Self signed certificate not trust anchor" );
                    logger.error( "subject: "
                            + currentCert.getSubjectDN().getName() );
                    success = false;
                    break;
                } else {
                    // this is the trust anchor
                    candidatePublicKey = currentCert.getPublicKey();
                    issuerCert = currentCert;
                }
            }

            logger.debug( "Checking chain" );

            if ( !currentCert.getIssuerX500Principal().equals(
                    issuerCert.getSubjectX500Principal() ) ) {
                logger
                        .error( "Certificate verification: issuing chain broken." );
                return false;
            }

            logger.debug( "Checking validity" );

            try {
                currentCert.checkValidity();
            } catch ( CertificateExpiredException e ) {
                logger.error(
                        "Certificate verification: certificate in chain expired. "
                                + e.getMessage(), e );
                logger.error( "Faulty certificate: "
                        + currentCert.getSubjectDN().getName() );
                logger.error( "End validity      : "
                        + currentCert.getNotAfter().toString() );
                return false;
            } catch ( CertificateNotYetValidException e ) {
                logger.error(
                        "Certificate verification: certificate in chain not yet valid. "
                                + e.getMessage(), e );
                logger.error( "Faulty certificate: "
                        + currentCert.getSubjectDN().getName() );
                logger.error( "Start validity      : "
                        + currentCert.getNotBefore().toString() );
                return false;
            }

            logger.debug( "Checking key" );

            try {
                currentCert.verify( candidatePublicKey );
            } catch ( Exception e ) {
                logger.error(
                        "Certificate verification: cannot verify signature. "
                                + e.getMessage(), e );
                logger.error( "Faulty certificate: "
                        + currentCert.getSubjectDN().getName() );
                return false;
            }

            logger.debug( "Checking revoked" );

            if ( isRevoked( currentCert, issuerCert ) ) {
                logger
                        .error( "Certificate verification: certificate in chain has been revoked." );
                logger.error( "Faulty certificate: "
                        + currentCert.getSubjectDN().getName() );
                return false;
            }

            boolean isCA = PKIUtils.isCA( issuerCert );

            logger.debug( "Checking CA " + isCA );
            if ( isCA ) {
                if ( !allowsPath( currentCert, issuerCert, constructedStack ) ) {
                    logger.error( "Certificate verification: subject '"
                                  + currentCert.getSubjectDN().getName()
                                  + "' not allowed by CA '"
                                  + issuerCert.getSubjectDN().getName() + "'" );
                    return false;
                }

                // check path length
                int maxPath = currentCert.getBasicConstraints();

                logger.debug( "stack.size = " + certStack.size()
                        + " maxPath = " + maxPath );

                if ( maxPath != -1 ) {
                    if ( maxPath < certStack.size() - proxyCount - 1  ) {
                        logger
                                .error( "Certificate verification: Maximum certification path length exceeded." );
                        success = false;
                        break;
                    }
                }
            } else {
                // not a ca. Maybe a proxy?
                logger.debug( "Checking for Proxy" );

                if ( !PKIUtils.isProxy( currentCert ) ) {
                    logger
                            .error( "Certificate verification: Non-proxy, non-CA certificate issued a certificate." );
                    return false;
                }
            }

            // check for unhandled critical extensions
            Set criticals = currentCert.getCriticalExtensionOIDs();
            if ( criticals != null ) {
                if ( !handledOIDs.containsAll( criticals ) ) {
                    logger
                            .error( "Certificate verification: Certificate contain unhandled critical extensions." );
                    return false;
                }
            }

            issuerCert = currentCert;
            candidatePublicKey = currentCert.getPublicKey();
            currentLength++;
            constructedStack.push(currentCert);
        }

        if ( !success )
            return false;

        return true;
    }

    private boolean allowsNamespaces(X509Certificate cert, X509Certificate issuer,
                                     Stack certStack) {

        // self signed certificates always pass.
        if (PKIUtils.selfIssued(cert))
            return true;

        Hashtable namespaces = caStore.getNamespaces();
        Namespace namespaceCandidate = (Namespace) namespaces.get(PKIUtils.getHash(issuer));
	  
        if (namespaceCandidate == null) {
            // specification says to travel up the chain in this case
            int size = certStack.size();
            int current = size-1;

            logger.debug("size = " + size + ", current = " + current + "\n");
            if (size > 0) {
                do {
                    namespaceCandidate = (Namespace)namespaces.get(PKIUtils.getHash(
                                          (X509Certificate)certStack.elementAt(current)));
                    current -= 1;
                } while (namespaceCandidate == null && current != -1);
            }

            if (namespaceCandidate == null) {
                //no candidates were found.  According to the rules, this is a permit
                return true;
            }
        }
        // at this point, namespaceCandidate != null

        int index = namespaceCandidate.findIssuer(issuer);

        while (index != -1) {
            logger.debug("looking inside namespace");
            namespaceCandidate.setCurrent(index);
            String subject = namespaceCandidate.getSubject();
            boolean permit = namespaceCandidate.getPermit();
            String currentSubj = PKIUtils.getOpenSSLFormatPrincipal(issuer.getSubjectDN());
            String currentSubjReversed = PKIUtils.getOpenSSLFormatPrincipal(issuer.getSubjectDN(), true);
            if (subject.equals(currentSubj) || subject.equals(currentSubjReversed)) {
                // this is the right policy
                return permit;
            }
            // no decision as of yet.  Look for other rules
            index = namespaceCandidate.findIssuer(issuer, index);
        }
        // candidates found, but no rule applies.  This is a deny
        return false;
    }

    private boolean allowsPath( X509Certificate cert, X509Certificate issuer,
				Stack certStack) {

        /* Self-signed certificates do not need to be checked against the signing policy. */
        if (PKIUtils.selfIssued(cert))
            return true;

        Hashtable signings = caStore.getSignings();

        SigningPolicy signCandidate = (SigningPolicy) signings.get( PKIUtils
                .getHash( issuer ) );

        logger.debug("signCandidate is: " + signCandidate);
        boolean matched = false;

        if (signCandidate == null)
            return allowsNamespaces(cert, issuer, certStack);

        if ( signCandidate != null ) {
            logger.debug("Class of issuer is : " + issuer.getClass());
            logger.debug("Class of Subject is: " + issuer.getSubjectDN().getClass());

            String issuerSubj = PKIUtils.getOpenSSLFormatPrincipal( issuer
                    .getSubjectDN() );
            logger.debug("Subject is : " + issuerSubj);

            Vector nameVector = getAllNames( cert );

            if ( nameVector == null )
                return false;

            logger.debug("Content of Vector is:" + nameVector);
            Iterator i = nameVector.iterator();

            while ( i.hasNext() ) {
                String certSubj = (String) i.next();

                logger.debug( "Examining: " + certSubj);
                logger.debug( "Looking for " + issuerSubj );
                int index = signCandidate.findIssuer( issuerSubj );
                if (index == -1) {
                    /* Work around different sources of certificates not 
                       agreeing on order of X500Name components. */
                    issuerSubj = PKIUtils.getOpenSSLFormatPrincipal(issuer
                                .getSubjectDN(), true);
                    index = signCandidate.findIssuer(issuerSubj);
                }
                                                                    
                while ( index != -1 ) {
                    logger.debug( "Inside index" );
                    signCandidate.setCurrent( index );
                    if ( signCandidate.getAccessIDCA().equals( issuerSubj ) ) {
                        Vector subjects = signCandidate.getCondSubjects();

                        Iterator subjIter = subjects.iterator();

                        while ( subjIter.hasNext() ) {
                            String subj = (String) subjIter.next();

                            logger.debug( "Comparing certSubj: '" + certSubj
                                    + "' to '" + subj + "'" );

                            subj = subj.replaceFirst( "\\*", "\\.\\*" );
                            if ( certSubj.toUpperCase().matches( subj.toUpperCase() ) ) {
                                matched = true;
                                logger.debug( "Subject: '" + certSubj
                                        + "' matches with subject: '" + subj
                                        + "' from signing policy." );
                                break;
                            }
                            
                            logger.debug( "Subject: '" + certSubj
                                    + "' does not match subject: '" + subj
                                    + "' from signing policy." );
                        }

                    }
                    index = signCandidate.findIssuer( issuerSubj, index );
                }

                if (matched) {
                    logger.debug("MATCHED AT LEAST ONCE");
                    break;
                }

            }

            nameVector.clear();
        }

        logger.debug("Value of Matched is: " + matched);
        return matched;
    }

    private Vector getAllNames( X509Certificate cert ) {

        if ( cert != null ) {
            Vector v = new Vector();
            v.add( PKIUtils.getOpenSSLFormatPrincipal( cert.getSubjectDN() ) );
            /* Sometime the format of the DN gets reversed. */
            v.add( PKIUtils.getOpenSSLFormatPrincipal( cert.getSubjectDN() , true));

            return v;
        }

        return null;
    }

    private boolean isRevoked( X509Certificate cert, X509Certificate issuer ) {

        Hashtable crls = caStore.getCRLs();
        Vector crllist = (Vector) ( crls.get( PKIUtils.getHash( issuer ) ) );

        boolean issued = false;

        if ( crllist != null ) {
            Iterator i = crllist.iterator();

            while ( i.hasNext() ) {

                X509CRL candidateCRL = (X509CRL) i.next();

                if ( candidateCRL != null ) {
                    try {
                        candidateCRL.verify( issuer.getPublicKey() );
                    } catch ( Exception e ) {
                        continue;
                    }

                    Set criticalExts = candidateCRL.getCriticalExtensionOIDs();

                    Set permittedCriticals = new HashSet();
                    permittedCriticals.add("2.5.29.28");

                    if ( criticalExts == null || criticalExts.isEmpty() ||
                         (!criticalExts.isEmpty() && permittedCriticals.containsAll(criticalExts))) {
                        if ( candidateCRL.getIssuerX500Principal().equals(
                                          issuer.getSubjectX500Principal() ) ) {
                            if ( candidateCRL.getNextUpdate().compareTo(
                                        new Date() ) >= 0
                                 && candidateCRL.getThisUpdate()
                                 .compareTo( new Date() ) <= 0 ) {

                                X509CRLEntry entry = candidateCRL
                                    .getRevokedCertificate( cert
                                        .getSerialNumber() );
                                if ( entry == null ) {
                                    return false;
                                }
                            }
                            else {
                                logger.error( "CRL for CA '"+issuer.getSubjectDN().toString()+"' has expired!" );
                            }
                        }
                    }
                    else {
                        logger.error("Critical extension found in crl!");
                        for (Iterator ii = criticalExts.iterator(); ii.hasNext();) {
                            logger.debug("Critical CRL Extension: " +
                                         (String)ii.next());
                        }

                    }
                    issued = true;
                }
            }
        }
        return issued;
    }
}
