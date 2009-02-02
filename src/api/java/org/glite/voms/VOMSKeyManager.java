/*********************************************************************
 *
 * Authors: Vincenzo Ciaschini - Vincenzo.Ciaschini@cnaf.infn.it
 *
 * Copyright (c) 2006 INFN-CNAF on behalf of the 
 * EGEE project.
 * For license conditions see LICENSE
 *
 * Parts of this code may be based upon or even include verbatim pieces,
 * originally written by other people, in which case the original header
 * follows.
 *
 *********************************************************************/

package org.glite.voms;

import javax.net.ssl.X509KeyManager;
import javax.net.ssl.KeyManagerFactory;
import java.security.cert.X509Certificate;
import java.security.Security;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;
import java.security.UnrecoverableKeyException;
import java.security.NoSuchProviderException;
//import java.io.FileCertReader;
import java.security.PrivateKey;
import javax.net.ssl.KeyManager;
import java.security.Principal;
import java.net.Socket;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.FileNotFoundException;
import java.security.NoSuchAlgorithmException;
import org.apache.log4j.Logger;

import org.glite.voms.contact.VOMSException;
import org.glite.voms.contact.UserCredentials;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class VOMSKeyManager implements X509KeyManager {
    private KeyManagerFactory keyManagerFactory = null;

    private X509KeyManager manager = null;

    private char[] passwd = null;

    private KeyStore keyStore = null;

    public static final int TYPE_PKCS12 = 1;
    public static final int TYPE_PEM    = 2;

    private static final Logger logger = Logger.getLogger(PKIUtils.class);

    static {
        if ( Security.getProvider( "BC" ) == null ) {
            Security.addProvider( new BouncyCastleProvider() );
        }
    }

    public VOMSKeyManager(String certfile, String keyfile, String password) {
        this(certfile, keyfile, password, TYPE_PEM);
    }

    public VOMSKeyManager(UserCredentials creds)
        throws NoSuchAlgorithmException, KeyStoreException,
               UnrecoverableKeyException, IOException,
               CertificateException {
        keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
        keyStore = KeyStore.getInstance("JKS");
        keyStore.load(null, "".toCharArray());
        logger.debug("ABOUT to set key entry");
        keyStore.setKeyEntry("alias", creds.getUserKey(), "".toCharArray(), creds.getUserChain());
        logger.debug("STORETYPE: " + keyStore.getType());
        keyManagerFactory.init(keyStore, "".toCharArray());
        manager = (X509KeyManager)keyManagerFactory.getKeyManagers()[0];
    }

    public VOMSKeyManager(String certfile, String keyfile, String password, int type) {
        try {
            keyManagerFactory = KeyManagerFactory.getInstance("SunX509");

            passwd = password.toCharArray();

            if (type == TYPE_PEM) {
                keyStore = keyStore.getInstance("JKS");
                keyStore = load(certfile, keyfile, passwd);
            }
            else if (type == TYPE_PKCS12) {
                keyStore = KeyStore.getInstance("PKCS12", "SunJSSE");
                keyStore.load(new FileInputStream(certfile), passwd);
            }

            keyManagerFactory.init(keyStore, passwd);
            manager = (X509KeyManager)keyManagerFactory.getKeyManagers()[0];
        }
        catch (Exception e) {
            throw new VOMSException("Cannot initialize VOMSKeyManager: ", e);
        }
    }

    private KeyStore createKeyStore(String cert, String key, char[] passwd) throws CertificateException, IOException {
        FileCertReader reader = new FileCertReader();

        X509Certificate[] certs = (X509Certificate [])(reader.readCerts(cert).toArray());

        PrivateKey pkey = null;
        KeyStore store = null;

        try {
            if (key != null)
                pkey = reader.readPrivateKey(cert);
            else
                pkey = reader.readPrivateKey(key);
        }
        catch(IOException e) {
            throw new VOMSException("Cannot load the private key.", e);
        }

        try {
            store = KeyStore.getInstance("JKS");
            store.setKeyEntry("alias", pkey, passwd, certs);
        } catch (KeyStoreException e) {
            throw new VOMSException("Cannot load the key pair.", e);
        }
        return store;
    }

    private KeyStore load(String certfile, String keyfile, char [] pwd) throws CertificateException, IOException {
        KeyStore store = null;

        if (certfile != keyfile) {
            store = createKeyStore(certfile, keyfile, pwd);
        }
        else {
            store = createKeyStore(certfile, certfile, pwd);
        }
        return store;
    }

    public String chooseClientAlias(String[] keytype, Principal[] issuers, Socket socket) {
        return manager.chooseClientAlias(keytype, issuers, socket);
    }

    public String chooseServerAlias(String keytype, Principal[] issuers, Socket socket) {
        return manager.chooseServerAlias(keytype, issuers, socket);
    }

    public X509Certificate[] getCertificateChain(String alias) {
        return manager.getCertificateChain(alias);
    }

    public String[] getClientAliases(String keytype, Principal[] issuers) {
        return manager.getClientAliases(keytype, issuers);
    }

    public String[] getServerAliases(String keytype, Principal[] issuers) {
        return manager.getServerAliases(keytype, issuers);
    }

    public PrivateKey getPrivateKey(String alias) {
        return manager.getPrivateKey(alias);
    }
}