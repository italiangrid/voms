/*********************************************************************
 *
 * Authors: Vincenzo Ciaschini - Vincenzo.Ciaschini@cnaf.infn.it
 *
 * Copyright (c) 2008-2009 INFN-CNAF on behalf of the 
 * EGEE I, II and III
 * For license conditions see LICENSE file or
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 *
 * Parts of this code may be based upon or even include verbatim pieces,
 * originally written by other people, in which case the original header
 * follows.
 *
 *********************************************************************/

package org.glite.voms;

import javax.net.ssl.X509TrustManager;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CRLException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;
import java.io.IOException;
import org.apache.log4j.Logger;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class VOMSTrustManager implements X509TrustManager {
    private PKIStore store = null;
    private PKIVerifier verifier = null;
    boolean stopcalled = false;

    private static Logger logger = Logger.getLogger( VOMSTrustManager.class
            .getName() );

    static {
        if ( Security.getProvider( "BC" ) == null ) {
            Security.addProvider( new BouncyCastleProvider() );
        }
    }

    public VOMSTrustManager(String dir) throws IOException, CertificateException, CRLException  {
        store = PKIStoreFactory.getStore(dir, PKIStore.TYPE_CADIR);
        verifier = new PKIVerifier(null, store);
        stopcalled = false;
    }

    public VOMSTrustManager(PKIStore castore) throws IOException, CertificateException, CRLException {
        verifier = new PKIVerifier(null, castore);
        store = castore;
        stopcalled = false;
    }

    public synchronized void stop() {
        if (!stopcalled) {
            verifier.cleanup();
            stopcalled = true;
        }
    }

    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        if (chain == null || authType == null ||
            chain.length == 0 || authType.length() == 0) {
            throw new IllegalArgumentException("One of the parameters is null or empty.");
        }

        if (logger.isDebugEnabled()) {
            logger.debug("Callying verify:");
            logger.debug("chain is:");

            for (int i =0; i < chain.length; i++) {
                logger.debug("HAVE TO VERIFY: " + chain[i].getSubjectDN());
            }
        }

        if (verifier.verify(chain))
            return;
        else {
            throw new CertificateException("Cannot verify certificate.  See log for details.");
        }
    }

    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        checkClientTrusted(chain, authType);
    }

    public X509Certificate[] getAcceptedIssuers() {
        Hashtable<String,Vector<X509Certificate>> CAs= store.getCAs();
        ArrayList<X509Certificate> certs= new ArrayList<X509Certificate>(CAs.size());

        for (Enumeration<Vector<X509Certificate>> certVectors= CAs.elements(); certVectors.hasMoreElements();) {
            Vector<X509Certificate> certVector= certVectors.nextElement();
            certs.addAll(certVector);
        }

        X509Certificate[] array= new X509Certificate[certs.size()];
        return certs.toArray(array); 
    }
}
