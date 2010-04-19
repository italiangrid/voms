/*********************************************************************
 *
 * Authors:
 *      Andrea Ceccanti - andrea.ceccanti@cnaf.infn.it
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
package org.glite.voms.contact;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;

import java.util.Enumeration;

import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PasswordFinder;
import org.bouncycastle.openssl.PEMWriter;

import org.glite.voms.PKIUtils;



/**
 * This class implements parsing and handling of X509 user credentials
 * in PEM or PKCS12 format.
 *
 * @author Andrea Ceccanti
 * @author Vincenzo Ciaschini
 *
 */
public class UserCredentials {

    static{
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private static final Logger log = Logger.getLogger( UserCredentials.class );

    private X509Certificate userCert;
    private X509Certificate[] userChain;

    private PrivateKey userKey;

    private UserCredentials(PrivateKey key, X509Certificate[] certs) {
        userKey = key;
        userCert = certs[0];
        userChain = certs;
        if (log.isDebugEnabled()) {
            log.debug("Cert is: " + certs[0].getSubjectDN());
            for (int i=0; i < userChain.length; i++) {
                log.debug("Chain["+i+"] is: " + userChain[i].getSubjectDN());
            }
        }

    }

    public void save(OutputStream os) throws IOException {
        OutputStreamWriter osw = new OutputStreamWriter(os);
        PEMWriter writer = new PEMWriter(osw);

        log.debug("Cert is: " + userCert.getSubjectDN());
        writer.writeObject(userCert);

	if (userKey != null)
	  writer.writeObject(userKey);

        for (int i=1; i < userChain.length; i++) {
            log.debug("Chain["+i+"] is: " + userChain[i].getSubjectDN());
            writer.writeObject(userChain[i]);
        }
        writer.flush();
    }

    /**
     *
     *  This method returs the user certificate loaded in this {@link UserCredentials}.
     *
     * @return the X509 user certificate.
     */
    public X509Certificate getUserCertificate() {

        return userCert;

    }
    /**
     *
     *  This method returs the user certificate chain loaded in this {@link UserCredentials}.
     *
     * @return the X509 user certificate.
     */
    public X509Certificate[] getUserChain() {

        return userChain;

    }


    /**
     *  This method returs the user credential openssl private key.
     *
     * @return the user credentials private key.
     */
    public PrivateKey getUserKey() {

        return userKey;

    }


    /**
     *
     * This method is used to load and parse an X509 certificate in PEM format.
     *
     * @param userCertFile the file object referring to the X509 certificate.
     */
    private void loadCert(File userCertFile){

        try {
            userChain = PKIUtils.loadCertificates(userCertFile);
            userCert = userChain[0];
        } catch ( CertificateException e ) {
            log.debug( "Error parsing user certificate: "
                    + e.getMessage() );

            if ( log.isDebugEnabled() )
                log.error( e.getMessage(), e );

            throw new VOMSException( e );
        }

    }

    private static class PFinder implements PasswordFinder {
        private String pwd;

        public PFinder(String password) {
            pwd = password;
        }

        public char [] getPassword() {
            if (pwd != null)
                return pwd.toCharArray();
            else
                return "".toCharArray();
        }
    }
    /**
     * This method is used to load and decrypt a user private key in PEM format.
     *
     * @param userKeyFile the file object that points to the PEM key.
     * @param password the password needed to decrypt the key.
     */
    private void loadKey(File userKeyFile, String password) {
            log.debug("File is: " + userKeyFile.getName());

            userKey = PKIUtils.loadPrivateKey(userKeyFile, new PFinder(password));
    }

    private void loadCredentials(File userCertFile, File userKeyFile, String keyPassword){

        loadCert( userCertFile );
        loadKey( userKeyFile, keyPassword );

    }

    private void loadPKCS12Credentials(File pkcs12File, String keyPassword){
        FileInputStream stream = null;
        try {

            KeyStore ks = KeyStore.getInstance( "PKCS12", "BC" );
            stream = new FileInputStream(pkcs12File);
            ks.load(stream, keyPassword.toCharArray());
            Enumeration aliases = ks.aliases();

            if (!aliases.hasMoreElements())
                throw new VOMSException("No aliases found inside pkcs12 certificate!");

            // Take the first alias and hope it is the right one...
            String alias = (String)aliases.nextElement();

            userChain = (X509Certificate[]) ks.getCertificateChain(alias);
            userCert  = (X509Certificate)   ks.getCertificate(alias);
            userKey   = (PrivateKey)        ks.getKey(alias, keyPassword.toCharArray());


        } catch ( Exception e ) {

            log.error( "Error importing pkcs12 certificate: "+e.getMessage() );

            if (log.isDebugEnabled())
                log.error( "Error importing pkcs12 certificate: "+e.getMessage(),e );

            throw new VOMSException(e);
        }
        finally {
            try {
                if (stream != null)
                    stream.close();
            }
            catch (IOException e) {
                /* do nothing */
            }
        }

    }

    private UserCredentials(UserCredentials credentials) {
        userChain = credentials.getUserChain();
        userKey   = credentials.getUserKey();
        userCert  = credentials.getUserCertificate();
    }

    private UserCredentials( String keyPassword ) {

        String x509UserCert = System.getProperty( "X509_USER_CERT", null );
        String x509UserKey = System.getProperty( "X509_USER_KEY", null );
        String x509UserKeyPassword = System.getProperty(
                "X509_USER_KEY_PASSWORD", null );

        String pkcs12UserCert = System.getProperty( "PKCS12_USER_CERT", null );
        String pkcs12UserKeyPassword = System.getProperty( "PKCS12_USER_KEY_PASSWORD", null );



        if ( x509UserCert != null && x509UserKey != null ){

            log.debug( "Looking for pem certificates in ("+x509UserCert+","+x509UserKey+")" );

            try{

                loadCredentials(new File( x509UserCert ), new File( x509UserKey ), (x509UserKeyPassword != null)? x509UserKeyPassword: keyPassword);
                log.debug( "Credentials loaded succesfully." );
                return;

            }catch (VOMSException e) {
                log.debug ("Error parsing credentials:"+e.getMessage());
                if (log.isDebugEnabled())
                    log.debug(e.getMessage(),e);
            }

        }

        log.debug( "Looking for pem certificates in "+System.getProperty( "user.home" )+File.separator+".globus" );

        File globusCert = new File (System.getProperty( "user.home" )+File.separator+".globus"+File.separator+"usercert.pem");
        File globusKey = new File (System.getProperty( "user.home" )+File.separator+".globus"+File.separator+"userkey.pem");

        try{

            loadCredentials( globusCert, globusKey, (x509UserKeyPassword != null)? x509UserKeyPassword: keyPassword);
            log.debug( "Credentials loaded succesfully." );
            return;

        }catch (VOMSException e) {
            log.debug ("Error parsing credentials:"+e.getMessage());
            if (log.isDebugEnabled())
                log.debug(e.getMessage(),e);
        }

        // PKCS12 credentials support
        if (pkcs12UserCert!=null){

            log.debug( "Looking for pkcs12 certificate in "+ pkcs12UserCert);
            File pkcs12File = null;

            try {

                pkcs12File = new File(System.getProperty( "user.home" )+File.separator+".globus" +File.separator+"usercert.p12");
                loadPKCS12Credentials( pkcs12File, (pkcs12UserKeyPassword != null)? pkcs12UserKeyPassword: keyPassword);
                log.debug( "Credentials loaded succesfully." );
                return;

            }catch(VOMSException e){
                log.debug ("Error parsing credentials from "+pkcs12File+":"+e.getMessage());
                if (log.isDebugEnabled())
                    log.debug(e.getMessage(),e);

            }

        }

        log.debug( "Looking for pkcs12 certificate in "+ System.getProperty( "user.home" )+File.separator+".globus"+File.separator+"usercert.p12");

        File pkcs12File = null;

        try {

            pkcs12File = new File(System.getProperty( "user.home" )+File.separator+".globus" +File.separator+"usercert.p12");
            loadPKCS12Credentials( pkcs12File, (pkcs12UserKeyPassword != null)? pkcs12UserKeyPassword: keyPassword);
            log.debug( "Credentials loaded succesfully." );
            return;

        }catch(VOMSException e){
            log.debug ("Error parsing credentials from "+pkcs12File+":"+e.getMessage());
            if (log.isDebugEnabled())
                log.debug(e.getMessage(),e);

        }

        throw new VOMSException("No user credentials found!");
    }

    private UserCredentials(String userCertFile, String userKeyFile, String keyPassword){

        loadCredentials( new File(userCertFile), new File(userKeyFile), keyPassword);
    }



    /**
     * Static instance constructor for a {@link UserCredentials}.
     * This method should be used with credentials whose private key is not encrypted.
     *
     * The current implementation looks for user credentials in the following places (in sequence):
     *
     * <ul>
     * <li> If the <code>X509_USER_CERT</code> and <code>X509_USER_KEY</code> system
     * properties are set, their values are used to load the user credentials
     * </li>
     *
     * <li>If the <code>PKCS12_USER_CERT</code> system property is set, its value is used to
     * load the user credentials.
     * </li>
     *
     * <li>The content of the <code>.globus</code> directory in the user's home is searched for a PEM certificate (in the
     * <code>usercert.pem</code> and <code>userkey.pem</code> files).
     * </li>
     *
     *  <li>The content of the .globus directory in the user's home is searched for a PKC12 certificate (in the
     * <code>usercert.p12</code>  file).
     * </li>
     * </ul>
     *
     * @return the loaded user credentials.
     *
     * @throws  VOMSException
     *          if there is an error loading the user credentials.
     */
    public static UserCredentials instance(){

        return new UserCredentials((String)null);
    }

    /**
     * Static instance constructor for a {@link UserCredentials}.
     * For more info on the user credentials load procedure, see {@link #instance()}.
     *
     * @param keyPassword the password that is to be used to decrypt the user private key.
     * @return the loaded user credentials.
     *
     * @throws  VOMSException
     *          if there is an error loading the user credentials.
     */
    public static UserCredentials instance(String keyPassword){

        return new UserCredentials(keyPassword);
    }



    /**
     *   Static instance constructor for a {@link UserCredentials}.
     *
     * This methods allows a user to bypass the default credentials search procedure (highlighted {@link #instance() here}),
     * by specifying the path to a PEM X509 user cert and private key.
     *
     * @param userCertFile the path to the PEM X509 user certificate.
     * @param userKeyFile the path to the PEM X509 private key.
     * @param keyPassword the password that is to be used to decrypt the user private key.
     * @return the loaded user credentials.
     *
     * @throws  VOMSException
     *          if there is an error loading the user credentials.
     *
     */
    public static UserCredentials instance(String userCertFile, String userKeyFile, String keyPassword){

        return new UserCredentials(userCertFile, userKeyFile, keyPassword);
    }

    /**
     *   Static instance constructor for a {@link UserCredentials}.
     *
     * This methods allows a user to bypass the default credentials search procedure (highlighted {@link #instance() here}),
     * by specifying the path to a PEM X509 user cert and private key.
     *
     * @param userCertFile the path to the PEM X509 user certificate.
     * @param userKeyFile the path to the PEM X509 private key.
     * @return the loaded user credentials.
     *
     * @throws  VOMSException
     *          if there is an error loading the user credentials.
     *
     */
    public static UserCredentials instance(String userCertFile, String userKeyFile){

        return UserCredentials.instance(userCertFile, userKeyFile, null);
    }

    /**
     *   Static instance constructor for a {@link UserCredentials}.
     *
     * This methods allows a user to bypass the default credentials search procedure (highlighted {@link #instance() here}),
     * by specifying the path to a PEM X509 user cert and private key.
     *
     * @param credentials the GlobusCredentials object containing the user's own proxy
     * @return the loaded user credentials.
     *
     * @throws  VOMSException
     *          if there is an error loading the user credentials.
     *
     */
    public static UserCredentials instance(UserCredentials credentials) {

        return new UserCredentials(credentials);
    }

    public static UserCredentials instance(PrivateKey key, X509Certificate[] certs) {
        return new UserCredentials(key, certs);
    }

}
