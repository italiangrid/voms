package org.glite.voms;

import javax.net.ssl.X509TrustManager;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CRLException;
import java.util.Hashtable;
import java.io.IOException;
import org.apache.log4j.Logger;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class VOMSTrustManager implements X509TrustManager {
    private PKIStore store = null;
    private PKIVerifier verifier = null;

    private static Logger logger = Logger.getLogger( PKIVerifier.class
            .getName() );

    static {
        if ( Security.getProvider( "BC" ) == null ) {
            Security.addProvider( new BouncyCastleProvider() );
        }
    }

    public VOMSTrustManager(String dir) throws IOException, CertificateException, CRLException  {
        verifier = new PKIVerifier();
        store = new PKIStore(dir, PKIStore.TYPE_CADIR);
        verifier.setCAStore(store);
    }

    public void stop() {
        verifier.cleanup();
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
        Hashtable CAs = store.getCAs();

        return (X509Certificate[])(CAs.values().toArray());
    }
}
