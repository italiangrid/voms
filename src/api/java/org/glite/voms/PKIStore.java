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

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.Security;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import java.util.Timer;
import java.util.TimerTask;
import java.util.Vector;

import javax.security.auth.x500.X500Principal;

import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.glite.voms.ac.VOMSTrustStore;

/**
 * PKIStore is the class serving to store all the components of a common PKI
 * installation, i.e.: CA certificates, CRLs, Signing policy files...
 *
 * It is also capable of storing files specific to the handling of VOMS
 * proxies, i.e. the content of the vomsdir diectory.
 *
 * @author Vincenzo Ciaschini
 */
public class PKIStore implements VOMSTrustStore {
    private Hashtable certificates = null;
    private Hashtable crls         = null;
    private Hashtable signings     = null;
    private Hashtable lscfiles     = null;
    private Hashtable vomscerts    = null;
    private Hashtable namespaces   = null;

    private int       instances    = 1;

    private static Logger logger = Logger.getLogger(PKIStore.class.getName());

    /**
     * This PKIStore object will contain data from a vomsdir directory.
     */
    public static final int TYPE_VOMSDIR = 1;

    /**
     * This PKIStore object will contain data from a CA directory.
     */
    public static final int TYPE_CADIR = 2;

    private static final int CERT      = 1;
    private static final int CRL       = 2;
    private static final int SIGN      = 3;
    private static final int LSC       = 4;
    private static final int NAMESPACE = 5;
    private static final int HASHCAPACITY = 75;

    private boolean aggressive = false;
    private Timer theTimer = null;

    private String certDir = null;
    private int type = -1;
    
    public static final String DEFAULT_VOMSDIR= File.separator
    + "etc" + File.separator + "grid-security" + File.separator
    + "vomsdir";
    
    public static final String DEFAULT_CADIR = File.separator
    + "etc" + File.separator + "grid-security" + File.separator
    + "certificates";

    /**
     * @return hashtable containing CA certificates.  The key is
     * the PKIUtils.getHash() of the subject of the CA.  The value is
     * a Vector containing all the CA certificates with the given hash.
     *
     * @see PKIUtils#getHash(X509Certificate cert)
     * @see PKIUtils#getHash(X500Principal principal)
     * @see PKIUtils#getHash(X509Principal principal)
     * @see java.util.Vector
     */
    public Hashtable getCAs() {
        return (Hashtable)certificates.clone();
    }

    /**
     * @return hashtable containing CRL.  The key is
     * the PKIUtils.getHash() of the issuer of the CRL.  The value is
     * a Vector containing all the CRL with the given hash.
     *
     * @see PKIUtils#getHash(X509Certificate cert)
     * @see PKIUtils#getHash(X500Principal principal)
     * @see PKIUtils#getHash(X509Principal principal)
     * @see java.util.Vector
     */

    public Hashtable getCRLs() {
        return crls;
    }

    /**
     * @return hashtable containing SigningPolicy objects.  The key is
     * the PKIUtils.getHash() of the issuer of the SigningPolicy.  The value is
     * a Vector containing all the CRL with the given hash.
     *
     * @see SigningPolicy
     * @see PKIUtils#getHash(X509Certificate cert)
     * @see PKIUtils#getHash(X500Principal principal)
     * @see PKIUtils#getHash(X509Principal principal)
     * @see java.util.Vector
     */

    public Hashtable getSignings() {
        return signings;
    }


    public Hashtable getNamespaces() {
        return namespaces;
    }

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }


    private class Refreshener extends TimerTask {
        public void run() {
            refresh();
        }
    }

    /**
     * Refreshes the content of the PKIStore object.
     *
     */
    public synchronized void refresh() {
        PKIStore newReader = null;

        /* The code below did not work.  In place changes to a file do not 
           change the lastmodified date of the directory, only the 
           lastaccessed, and java does not provide a way to determine the
           latter. */
        /*
        File f = new File(certDir);

        if (f.lastModified() == lastmodified) {
            logger.debug("No changes to directory -- Do not refresh");
            return;
        }
        */
        try {
            newReader = new PKIStore(certDir, type, aggressive, false);
        } 
        catch (Exception e) {
            logger.error("Cannot refresh store: " + e.getMessage());
            return;
        }
        finally {
            if (newReader != null)
                newReader.stopRefresh();
        }
        
        try {
            certificates.clear();
            certificates = newReader.certificates;
            newReader.certificates = null;

            crls.clear();
            crls = newReader.crls;
            newReader.crls = null;

            signings.clear();
            signings = newReader.signings;
            newReader.signings = null;

            lscfiles.clear();
            lscfiles = newReader.lscfiles;
            newReader.lscfiles = null;

            vomscerts.clear();
            vomscerts = newReader.vomscerts;
            newReader.vomscerts = null;

            namespaces.clear();
            namespaces = newReader.namespaces;
            newReader.namespaces = null;


        }
        finally {
            newReader = null;
        }
    }

    PKIStore(String dir, int type, boolean aggressive, boolean timer)  throws IOException, CertificateException, CRLException {
        this.aggressive = aggressive;
        certificates = new Hashtable(HASHCAPACITY);
        crls         = new Hashtable(HASHCAPACITY);
        signings     = new Hashtable(HASHCAPACITY);
        lscfiles     = new Hashtable(HASHCAPACITY);
        vomscerts    = new Hashtable(HASHCAPACITY);
        namespaces   = new Hashtable(HASHCAPACITY);

        if (type != TYPE_VOMSDIR &&
            type != TYPE_CADIR)
            throw new IllegalArgumentException("Unsupported value for type parameter in PKIReader constructor");

        if ((dir == null) || dir.equals("")) {
            if (type == TYPE_VOMSDIR) {
                dir = System.getProperty("VOMSDIR");
                if (dir == null)
                    dir = DEFAULT_VOMSDIR;
            }
            else if (type == TYPE_CADIR) {
                dir = System.getProperty("CADIR");
                if (dir == null)
                    dir = DEFAULT_CADIR;
            }
        }

        logger.info("Initializing "+ ((type == TYPE_VOMSDIR) ? "VOMS": "CA") + " certificate store from directory: "+dir);
        
        // Some sanity checks on VOMSDIR and CA dir
        File theDir = new File(dir);
        
        if (!theDir.exists()){
         
            if (type == TYPE_CADIR) {
                StringBuilder message = new StringBuilder();
                message.append("Directory ");
                message.append(dir);
                message.append(" doesn't exist on this machine!");
                message.append(" Please specify a value for the cadir directory or set the CADIR system property.");
                throw new FileNotFoundException(message.toString());
            }
            else {
                logger.warn("Please specify a value for the vomsdir directory or set the VOMSDIR system property.");
            }
            
        }
        
        if (theDir.exists()) {
            if (!theDir.isDirectory()){
            
                throw new IllegalArgumentException(((type == TYPE_VOMSDIR)? "Voms certificate" : "CA certificate")+ 
                                                   " directory passed as argument is not a directory! ["+theDir.getAbsolutePath()+"]");
            }
        }
        
        if (theDir.exists()) {
            if (theDir.list().length == 0){
                if (type == TYPE_CADIR)
                    throw new IllegalArgumentException("CA certificate directory passed as argument is empty! [" +
                                                       theDir.getAbsolutePath()+"]");
                else {
                    logger.warn("Voms certificate directory passed as argument is empty! [" +
                                theDir.getAbsolutePath() + "]");
                    logger.warn("Validation of VOMS Attribute Certificate will likely fail.");
                }
            }
        }

        certDir = dir;
        this.type = type;

        if (theDir.exists())
            load();



        if (timer) {
            theTimer = new Timer(true);
            theTimer.scheduleAtFixedRate(new Refreshener(), 30000, 30000);
        }
        instances = 1;
    }

    /**
     * @param dir        -- The directory from which to read the files.
     *                      If null or the empty string, this will default
     *                      to "/etc/grid-security/certificates" if type is
     *                      TYPE_CADIR, or "etc/grid-security/vomsdir" if
     *                      type is TYPE_VOMSDIR.
     * @param type       -- either TYPE_CADIR for CA certificates,
     *                      or TYPE_VOMSDIR for VOMS certificate.
     * @param aggressive -- if true, loading of data will continue even if
     *                      a particular file could not be loaded, while if
     *                      false loading will stop as soon as an error occur.
     *
     * @throws IOException if type is neither TYPE_CADIR nor TYPE_VOMSDIR.
     * @throws CertificateException if there are parsing errors while loading
     *                              a certificate.
     * @throws CRLException if there are parsing errors while loading a CRL.
     */
    public PKIStore(String dir, int type, boolean aggressive) throws IOException, CertificateException, CRLException {
        this(dir, type, aggressive, true);
    }

    /**
     * This is equivalent to PKIStore(dir, type, true)
     *
     * @see #PKIStore(String dir, int type, boolean aggressive)
     */
    public PKIStore(String dir, int type) throws IOException, CertificateException, CRLException {
        this(dir, type, true, true); 
    }

    public PKIStore(int type) throws IOException, CertificateException, CRLException {
        this(null, type, true, true);
    }

    public PKIStore() {
        aggressive = true;
        certificates = new Hashtable(HASHCAPACITY);
        crls         = new Hashtable(HASHCAPACITY);
        signings     = new Hashtable(HASHCAPACITY);
        lscfiles     = new Hashtable(HASHCAPACITY);
        vomscerts    = new Hashtable(HASHCAPACITY);
        namespaces   = new Hashtable(HASHCAPACITY);
        instances = 1;
    }


    /**
     * Changes the interval between refreshes of the store.
     *
     * @param millisec New interval (in milliseconds)
     */

    public void rescheduleRefresh(int millisec) {
        if (theTimer != null)
            theTimer.cancel();
        theTimer = null;

        theTimer = new Timer(true);
        theTimer.scheduleAtFixedRate(new Refreshener(), millisec, millisec);
    }

    /**
     * Stop all refreshes.
     *
     * NOTE: This method must ALWAYS be called prior to disposing of a PKIStore
     * object.  The penalty for not doing it is a memor leak.
     */
    public void stopRefresh() {
        if (instances != 0)
            instances --;

        if (instances == 0) {
            if (theTimer != null)
                theTimer.cancel();
            theTimer = null;
        }
    }

    protected void addInstance() {
        instances++;
    }

    /**
     * Changes the aggressive mode of the store.
     *
     * @param b -- if true (default) load as much as possible,
     *             otherwise stop loading at the first error.
     */
    public void setAggressive(boolean b) {
        aggressive = b;
    }

    private static class Couple {
        Object first;
        Object second;

        Couple(Object first, Object second) {
            this.first = first;
            this.second = second;
        }
    }

    /**
     * Gets the LSC file corresponding to the given VO, for the given
     * server.
     *
     * @param voName   -- The name of the VO.
     * @param hostName -- The hostName of the issuing server.
     *
     * @return The corresponding LSCFile object, or null if none is present.
     */
    public LSCFile getLSC(String voName, String hostName) {
        Hashtable lscList = (Hashtable)lscfiles.get(voName);

        if (lscList != null) {
            return (LSCFile)lscList.get(hostName);
        }
        return null;
    }

    /**
     * Gets an array of candidate issuer certificates for an AC with the
     * given issuer and belonging to the given VO.
     *
     * @param issuer The issuer of the AC.
     * @param voName The name of the VO.
     *
     * @return the array of candidates, or null if none is found.
     */
    public X509Certificate[] getAACandidate(X500Principal issuer, String voName) {
        Hashtable listCerts = (Hashtable)vomscerts.get(PKIUtils.getHash(issuer));

        if (logger.isDebugEnabled())
            logger.debug("listcerts content: " + listCerts);
        if (listCerts != null) {
            HashSet certSet = (HashSet)listCerts.get(voName);
            if (certSet == null)
                certSet = (HashSet)listCerts.get("");

            if (certSet != null)
                return (X509Certificate[])certSet.toArray(new X509Certificate[] {});
        }
        return null;
    }

    /**
     * Loads the files from the directory specified in the constructors
     *
     * @throws IOException if type is neither TYPE_CADIR nor TYPE_VOMSDIR.
     * @throws CertificateException if there are parsing errors while loading
     *                              a certificate.
     * @throws CRLException if there are parsing errors while loading a CRL.
     */

    public void load() throws IOException, CertificateException, CRLException  {
        switch (type) {
        case TYPE_VOMSDIR:
            getForVOMS(new File(certDir), null);
            break;
        case TYPE_CADIR:
            getForCA(new File(certDir));
            break;
        default:
            break;
        }
    }

    private void load(X509Certificate cert, String voname) {
        if (cert == null)
            return;

        if (logger.isDebugEnabled())
            logger.debug("CERT = " + cert + " , vo = " + voname);

        String hash = PKIUtils.getHash(cert);

        if (logger.isDebugEnabled()) {
            logger.debug("Registered HASH: " + hash +
                         " for " + cert.getSubjectDN().getName() +
                         " for vo: " + voname);
            logger.debug("Class of getSubjectDN: " + cert.getSubjectDN().getClass());
            logger.debug("KNOWN HASH ? " + vomscerts.containsKey(hash));
            logger.debug("VOMSCERTS = " + vomscerts);
        }

        if (vomscerts.containsKey(hash)) {
            logger.debug("Already exixtsing HASH");

            Hashtable certList = (Hashtable)vomscerts.get(hash);
            HashSet voSet = (HashSet)certList.get(voname);
            if (voSet != null)
                voSet.add(cert);
            else {
                HashSet set = new HashSet();
                set.add(cert);
                certList.put(voname, set);
            }
        }
        else {
            logger.debug("Originally EMPTY table");

            Hashtable certList = new Hashtable(HASHCAPACITY);
            HashSet set = new HashSet();
            set.add(cert);
            certList.put(voname, set);
            vomscerts.put(hash, certList);

            if (logger.isDebugEnabled()) {
                logger.debug("Inserted HASH: " + hash);
                logger.debug("NEW VOMSCERTS = " + vomscerts);
            }
        }
    }

    private void load(X509Certificate[] certs, String voname) {
        int len = certs.length;
        logger.debug("LEN = " +len);

        for (int i =0; i < len; i++) {

            if (logger.isDebugEnabled())
                logger.debug("PARSING: " + i + " value: " + (Object)certs[i]);

            load(certs[i], voname);
        }
    }


    private void load(X509Certificate cert) {
        String hash = PKIUtils.getHash(cert);

        if (certificates.containsKey(hash)) {
            ((Vector)certificates.get(hash)).add(cert);
        }
        else {
            Vector certs = new Vector();
            certs.add(cert);
            certificates.put(hash, certs);
        }
    }

    private void load(X509Certificate[] certs) {
        int len = certs.length;

        for (int i = 0; i < len; i++) {
            load(certs[i]);
        }
    }

    private void load(X509CRL crl) {
        String hash = PKIUtils.getHash(crl);

        if (crls.containsKey(hash)) {
            ((Vector)crls.get(hash)).add(crl);
        }
        else {
            Vector c = new Vector();
            c.add(crl);
            crls.put(hash, c);
        }
    }

    private void load(SigningPolicy sp) {
        String key = sp.getName();

        signings.put(key, sp);
    }

    private void load(Namespace nsp) {
        String key = nsp.getName();

	namespaces.put(key, nsp);
    }

    private void load(LSCFile lsc, String vo) {
        String key = lsc.getName();
        Hashtable lscList = null;

        if (!lscfiles.containsKey(vo)) {
            lscList = new Hashtable();
            lscfiles.put(vo, lscList);
        }

        if (lscList == null)
            lscList = (Hashtable)lscfiles.get(vo);

        lscList.put(key, lsc);
    }

    private void getForCA(File file) throws IOException, CertificateException, CRLException {
        File[] files = file.listFiles();
        Iterator contents = Arrays.asList(files).iterator();

        while (contents.hasNext()) {
            File f = (File)contents.next();

            logger.debug("filename: " + f.getName());

            try {
                Couple c = getObject(f);
                if (c != null) {
                    int value = ((Integer)c.second).intValue();
                    logger.debug("TYPE: " + value);

                    if (value == CRL)
                        load((X509CRL)c.first);
                    else if (value == CERT) {
                        X509Certificate[] arr = new X509Certificate[0];
                        load((X509Certificate[])((List)(c.first)).toArray(arr));
                    }
                    else if (value == SIGN) {
                        load((SigningPolicy)c.first);
                    }
		    else if (value == NAMESPACE) {
		        load((Namespace)c.first);
		    }
                }
            }
            catch(IOException e) {
                logger.error(e.getMessage(), e);
                f = null;
                if (!aggressive)
                    throw e;
            }
            catch(CRLException e) {
                logger.error(e.getMessage(), e);
                f = null;
                if (!aggressive)
                    throw e;
            }
            catch(CertificateException e) {
                logger.error(e.getMessage(), e);
                f = null;
                if (!aggressive)
                    throw e;
            }
        }
    }


    private void getForVOMS(File file, String vo) throws IOException, CertificateException, CRLException  {
        File[] files = file.listFiles();
        Iterator contents = Arrays.asList(files).iterator();
        if (vo == null)
            vo="";

        logger.debug("For VO: " + vo);

        while (contents.hasNext()) {
            File f = (File)contents.next();
            try {
                logger.debug("NAME: " + f.getName());

                if (!f.isDirectory()) {
                    Couple c = getObject(f);
                    if (c != null) {
                        int value = ((Integer)c.second).intValue();
                        logger.debug("TYPE: " + value);

                        if (value == CERT) {
                            X509Certificate[] arr = new X509Certificate[0];
                            load((X509Certificate[])((List)(c.first)).toArray(arr), vo);
                        }
                        else if (value == LSC) {
                            load((LSCFile)c.first, vo);

                            if (logger.isDebugEnabled()) {
                                Vector v = ((LSCFile)c.first).getDNLists();
                                ListIterator li = v.listIterator();
                                int i = 0;
                                while (li.hasNext()) {
                                    logger.debug("Sequence: " + i);
                                    Vector w = (Vector)li.next();
                                    ListIterator li2 = w.listIterator();
                                    while (li2.hasNext())
                                        logger.debug("DN: " + (String)li2.next());
                                }
                            }
                        }
                    }
                }
                else if (vo.equals(""))
                    getForVOMS(f, f.getName());
                f = null;
            }
            catch(CertificateException e) {
                logger.error(e.getMessage(), e);
                f = null;

                if (!aggressive)
                    throw e;
            }
            catch(CRLException e) {
                logger.error(e.getMessage(), e);
                f = null;

                if (!aggressive)
                    throw e;
            }
            catch(IOException e) {
                logger.error(e.getMessage(), e);
                f = null;

                if (!aggressive)
                    throw e;
            }
        }
    }

    private Couple getObject(File f) throws IOException, CertificateException, CRLException {
        if (f.getName().matches(".*\\.lsc")) {
            return new Couple(new LSCFile(f), Integer.valueOf(LSC));
        }

        if (f.getName().matches(".*\\.signing_policy")) {
            return new Couple(new SigningPolicy(f), Integer.valueOf(SIGN));

        }

	if (f.getName().matches(".*\\.namespace")) {
	    return new Couple(new Namespace(f), Integer.valueOf(NAMESPACE));
	}

        Object o = null;
        try {
            o = PKIUtils.readObject(f);
        }
        catch(FileNotFoundException e) {
            logger.error("Problem reading file " + f.getName() +
                         ": " + e.getMessage());
            return null;
        }

        if (o instanceof X509CRL)
            return new Couple(o, Integer.valueOf(CRL));

        if (o instanceof List)
            return new Couple(o, Integer.valueOf(CERT));

        return null;
    }
}
        
