/*
 * Copyright (c) Members of the EGEE Collaboration. 2004.
 * See http://eu-egee.org/partners/ for details on the copyright holders.
 * For license conditions see the license file or http://eu-egee.org/license.html
 */

/*
 * Copyright (c) 2002 on behalf of the EU DataGrid Project:
 * The European Organization for Nuclear Research (CERN),
 * the Particle Physics and Astronomy Research Council (PPARC),
 * the Helsinki Institute of Physics and
 * the Swedish Research Council (SRC). All rights reserved.
 * see LICENSE file for details
 *
 * DirectoryList.java
 *
 * @author  Joni Hahkala
 * Created on December 10, 2001, 6:50 PM
 */
/*
 * Copyright (c) 2002 on behalf of the EU DataGrid Project:
 * The European Organization for Nuclear Research (CERN),
 * the Particle Physics and Astronomy Research Council (PPARC),
 * the Helsinki Institute of Physics and
 * the Swedish Research Council (SRC). All rights reserved.
 * see LICENSE file for details
 *
 * FileEndingIterator.java
 *
 * @author  Joni Hahkala
 * Created on December 3, 2001, 9:16 AM
 */
/*
 * Copyright (c) 2002 on behalf of the EU DataGrid Project:
 * The European Organization for Nuclear Research (CERN),
 * the Particle Physics and Astronomy Research Council (PPARC),
 * the Helsinki Institute of Physics and
 * the Swedish Research Council (SRC). All rights reserved.
 * see LICENSE file for details
 *
 * FileCertReader.java
 *
 * @author  Joni Hahkala
 * Created on March 27, 2002, 8:24 PM
 */

package org.glite.security.voms;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.Timer;
import java.util.TimerTask;
import java.util.Vector;

import javax.security.auth.x500.X500Principal;

import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.glite.security.voms.ac.ACTrustStore;

/** Lists all the files in the given directory that end with
 * a certain ending.
 */
class FileEndingIterator {
    static Logger logger = Logger.getLogger(FileEndingIterator.class.getName());

    /** The file ending.
     */
    protected String ending;

    /** A flag to show that there are more files that match.
     */
    protected boolean nextFound = false;

    /** The list of files in the directory.
     */
    protected File[] fileList;

    /** The index of the next match in the fileList.
     */
    protected int index = 0;

    /** Creates new FileIterator and searches the first match.
     * @param path The directory used for the file search.
     * @param ending The file ending to search for.
     */
    public FileEndingIterator(String path, String ending) {
        this.ending = ending;

        try {
            // open the directory
            File directory = (path.length() != 0) ? new File(path) : new File(".").getAbsoluteFile();

            // list the files and dirs inside
            fileList = directory.listFiles();

            // find the first match for the ending
            nextFound = findNext();
        } catch (Exception e) {
            logger.error("no files found from \"" + path + "\" error: " + e.getMessage());

            //            e.printStackTrace();
            return;
        }
    }

    /** Used to get the next matching file.
     * @return Returns the next matching file.
     */
    public File next() {
        if (nextFound == false) {
            return null;
        }

        File current = fileList[index++];

        nextFound = findNext();

        return current;
    }

    /** Used to check that there are more matching files to get
     * using next().
     * @return Returns true if there are more matching files.
     */
    public boolean hasNext() {
        return nextFound;
    }

    /** Finds the next matching file in the list of files.
     * @return Returns true if a matching file was found.
     */
    protected boolean findNext() {
        try {
            // search the next file with proper ending
            while ((index < fileList.length) &&
                    (fileList[index].isDirectory() || !fileList[index].getName().endsWith(ending))) {
                //               System.out.println("FileIterator::next: Skipping file " + fileList[index].getName());
                index++;
            }
        } catch (Exception e) {
            logger.error("Error while reading directory " + e.getMessage());

            //            e.printStackTrace(System.out);
            return false;
        }

        // check if the loop ended because of a match or because running out of choices.
        if (index < fileList.length) {
            return true;
        }

        return false;
    }
}

/** Reads all certificates from given files, accepts binary form of DER encoded certs and
 * the Base64 form of the DER encoded certs (PEM). The base64 certs can contain garbage in front of
 * the actual certificate that has to begin with "-----BEGIN".
 * Should accept multiple certs in one file, not tested!
 */
class FileCertReader {
    static Logger logger = Logger.getLogger(FileCertReader.class.getName());
    static final int BUF_LEN = 1000;
    static final byte CARR = '\r';
    static final byte NL = '\n';

    /** The type for TrustAnchor
     */
    static final int TYPE_ANCHOR = 100;

    /** The type for certificate revocation list
     */
    static final int TYPE_CRL = 101;

    /** the type for X509 certificate
     */
    static final int TYPE_CERT = 102;

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    CertificateFactory certFactory;

    /** Creates a new instance of CertReader. */
    public FileCertReader() throws CertificateException {
        try {
            certFactory = CertificateFactory.getInstance("X.509", "BC");
        } catch (Exception e) {
            logger.error("Error while creating a FileCertReader: " + e.getMessage());
            throw new CertificateException("Error while creating a FileCertReader: " +
                e.getMessage());
        }
    }

    /**
     * Creates a new instance of CertReader with the
     * specified provider.
     *
     * @param provider   the provider to be used in creating the
     *                   certificates etc.
     */
    public FileCertReader(Provider provider) throws CertificateException {
        try {
            certFactory = CertificateFactory.getInstance("X.509", provider);
        } catch (Exception e) {
            logger.error("Error while creating a FileCertReader: " + e.getMessage());
            throw new CertificateException("Error while creating a FileCertReader: " +
                e.getMessage());
        }
    }

    /**
     * Creates a new instance of CertReader with the
     * specified provider
     *
     * @param provider   the provider to be used in creating the
     *                   certificates etc.
     */
    public FileCertReader(String provider) throws CertificateException {
        try {
            certFactory = CertificateFactory.getInstance("X.509", provider);
        } catch (Exception e) {
            logger.error("Error while creating a FileCertReader: " + e.getMessage());
            throw new CertificateException("Error while creating a FileCertReader: " +
                e.getMessage());
        }
    }

    /** Reads the certificates from the files defined in the
     * argument. See DirectoryList for file definition format.
     * @param files The file definition.
     * @throws Exception Thrown if certificate reading from the files
     * fails.
     * @return Returns the Vector of certificates read.
     * @see org.glite.security.util.DirectoryList
     */
    public Vector readCerts(String files) throws IOException, CertificateException {
        Vector certs = readFiles(files, TYPE_CERT);

        Iterator certIter = certs.iterator();

        logger.debug("read certs: ");

        while (certIter.hasNext()) {
            X509Certificate cert = (X509Certificate) certIter.next();
            logger.debug("Read cert: " + cert.getSubjectDN().toString());
        }

        return certs;
    }

    /** Reads the certificates from the files defined in the
     * argument and makes TrustAnchors from them. See
     * DirectoryList for file definition format.
     * @param files The file definition.
     * @throws Exception Thrown if the certificate reading fails.
     * @return Returns a Vector of TrustAnchors read from the
     * files.
     * @see org.glite.security.util.DirectoryList
     */
    public Vector readAnchors(String files) throws IOException, CertificateException {
        Vector anchors = readFiles(files, TYPE_ANCHOR);

        Iterator anchorIter = anchors.iterator();

        logger.debug("read TrustAnchors: ");

        while (anchorIter.hasNext()) {
            TrustAnchor anchor = (TrustAnchor) anchorIter.next();
            logger.debug("Read TrustAnchor: " + anchor.getTrustedCert().getSubjectDN().toString());
        }

        return anchors;
    }

    /** Reads the certificate revocation lists (CRLs) from the
     * files defined in the argument. See DirectoryList for
     * file definition format.
     * @param files The file definition.
     * @throws Exception Thrown if the CRL reading failed.
     * @return Returns a vector of CRLs read from the files.
     * @see org.glite.security.util.DirectoryList
     */
    public Vector readCRLs(String files) throws IOException, CertificateException {
        Vector crls = readFiles(files, TYPE_CRL);

        Iterator crlIter = crls.iterator();

        logger.debug("read CRLs: ");

        while (crlIter.hasNext()) {
            X509CRL crl = (X509CRL) crlIter.next();
            logger.debug("Read CRL: " + crl.getIssuerDN().toString());
        }

        return crls;
    }

    /** Reads the certificates or CRLs from the files defined by
     * the first argument, see DirectoryList for file definition
     * format.
     * @param files The file definition.
     * @param type The type of things to read from the files.
     * Currently supported are TYPE_ANCHOR,
     * TYPE_CRL and TYPE_CERT defined in this class.
     * @throws CertificateException Thrown if the reading of files fails.
     * @return Returns a Vector of objects of type given that
     * were read from the files given.
     * @see org.glite.security.util.DirectoryList
     */
    private Vector readFiles(String files, int type) throws CertificateException {
        Vector storeVector = new Vector();

        try {
            // load CA certificates
            //            System.out.println("Reading CA certificates");
            DirectoryList dir = new DirectoryList(files); // get the list of files matching CAFiles

            Iterator CAFileIter = dir.getListing().iterator();

            // create a iterator that returns inputsteam for all the files from dir CAPath with ending CAEnding
            //            FileEndingIterator CAFileIter = new FileEndingIterator(CAPath, CAEnding);
            // go through the files
            while (CAFileIter.hasNext()) { // go through the files reading the certificates

                File nextFile = (File) CAFileIter.next();

                storeVector.addAll(readFile(nextFile, type));
            }
        } catch (IOException e) {
            logger.fatal("Error while reading certificates or CRLs: " + e.getMessage());

            //            e.printStackTrace();
            throw new CertificateException("Error while reading certificates or CRLs: " +
                e.getMessage());
        }

        return storeVector;
    }

    /** Reads the objects of given type from the File.
     * @param certFile The file to read.
     * @param type The type of objects to read form the file.
     * @throws IOException Thrown if the reading of objects of given type
     * fails.
     * @return Returns the Vector of objects read form the file.
     */
    public Vector readFile(File certFile, int type) throws IOException {
        //                System.out.println("Opening " + nextFile.toString());
        BufferedInputStream binStream = null;
        Vector objects = new Vector();

        try {
            // get the buffered stream to facilitate marking
            binStream = new BufferedInputStream(new FileInputStream(certFile));

            while (binStream.available() > 0) {
                Object obj = objectReader(binStream, type);

                if (obj != null) {
                    objects.add(obj);
                }

                skipEmptyLines(binStream);
            }
        } catch (Exception e) {
            logger.fatal("Error while reading certificates or crls from file " +
                certFile.toString() + "error was: " + e.getMessage());

            //            e.printStackTrace();
            throw new IOException("Error while reading certificates or crls from file " +
                certFile.toString() + "error was: " + e.getMessage());
        } finally {
            if (binStream != null) {
                binStream.close();
            }
        }

        return objects;
    }

    /** Reads a certificate or a CRL from the stream, doing some
     * error correction.
     * @param binStream The stream to read the object from.
     * @param type The type of object to read from the stream.
     * @throws CertificateException Thrown if an error occurs while reading the object.
     * @throws IOException Thrown if an error occurs while reading the object.
     * @return Returns the object read.
     */
    public Object objectReader(BufferedInputStream binStream, int type)
        throws CertificateException, IOException {
        Object object = null;
        int errors = 0; // no errors in the beginning
        binStream.mark(10000);

        do { // try twice, first with plain file (reads binary and plain Base64 certificates,
             // second with skipping possible garbage in the beginning.

            try {
                if (errors == 1) { // if the first try failed, try if it was because of garbage in the beginning
                    // before the actual base64 encoded certificate
                    errors = 2; // if this try fails, don't try anymore

                    skipToCertBeginning(binStream); // skip the garbage
                }

                byte[] b = new byte[1000];
                binStream.mark(100000);

                /*                            System.out.println("The file contains:--------------");
                   while(binStream.available()>0){
                       int num = binStream.read(b);
                       System.out.println(new String(b, 0, num));
                   }
                   System.out.println("The file ends-------------------");
                 */
                binStream.reset();

                //                                System.out.println("Reading certificate form file"  + nextFile.toString() + " Available bytes:" + binStreamCA.available());
                object = readObject(binStream, type);
            } catch (Exception e) {
                if (errors != 0) { // if the error persists after first pass, fail
                    //                    e.printStackTrace();
                    logger.error("Certificate or CRL reading failed: " + e.getMessage());
                    throw new CertificateException("Certificate or CRL reading failed: " +
                        e.getMessage());
                }

                //                                System.out.println("Trying again");
                errors = 1; // first try failed, try again with skipping
                binStream.reset(); // rewind the file to the beginning of this try
            }
        } while (errors == 1); // try again after first try

        return object;
    }

    /** Does the actual reading of the object.
     * @param binStream The stream to read the object from.
     * @param type The type of the object.
     * @throws CertificateException Thrown if there is a problem reading the object.
     * @return Returns the object read or null if no object was found.
     */
    public Object readObject(BufferedInputStream binStream, int type)
        throws CertificateException {
        Object obj;

        if (type == TYPE_CRL) { // reading certificate revocation lists

            try {
                obj = certFactory.generateCRL(binStream);
            } catch (CRLException e) {
                logger.error("CRL loading failed: " + e.getMessage());
                throw new CertificateException(e.getMessage());
            }
        } else { // reading certs or trust anchors

            X509Certificate cert = (X509Certificate) certFactory.generateCertificate(binStream); // try to read the certificate

            if (cert == null) {
                return null;
            }

            if (type == TYPE_ANCHOR) {
                // add the certificate to trustanchors, no name contstraints (should add the nameconstraints!)
                obj = new TrustAnchor(cert, null);
            } else {
                if (type == TYPE_CERT) {
                    obj = cert;
                } else {
                    logger.fatal("Internal error: Invalid data type " + type +
                        " when trying to read certificate");
                    throw new CertificateParsingException("Internal error: Invalid data type " +
                        type + " when trying to read certificate");
                }
            }
        }

        return obj;
    }

    /** Skips everything in front of "-----BEGIN" in the stream.
     * @param stream The stream to read and skip.
     * @throws IOException Thrown if there is a problem skipping.
     */
    static public void skipToCertBeginning(BufferedInputStream stream)
        throws IOException {
        byte[] b = new byte[BUF_LEN]; // the byte buffer
        stream.mark(BUF_LEN + 2); // mark the beginning

        while (stream.available() > 0) { // check that there are still something to read

            int num = stream.read(b); // read bytes from the file to the byte buffer
            String buffer = new String(b, 0, num); // generate a string from the byte buffer
            int index = buffer.indexOf("----BEGIN"); // check if the certificate beginning is in the chars read this time

            if (index == -1) { // not found
                //                System.out.println("skipping:" + buffer);
                stream.reset(); // rewind the file to the beginning of the last read
                stream.skip(BUF_LEN - 100); // skip only part of the way as the "----BEGIN" can be in the transition of two 1000 char block
                stream.mark(BUF_LEN + 2); // mark the new position
            } else { // found

                while ((buffer.charAt(index - 1) == '-') && (index > 0)) { // search the beginnig of the ----BEGIN tag
                    index--;

                    if (index == 0) { // prevent charAt test when reaching the beginning of buffer

                        break;
                    }
                }

                //                System.out.println("Last skip:" + buffer.substring(0, index));
                stream.reset(); // rewind to the beginning of the last read
                stream.skip(index); // skip to the beginning of the tag
                stream.mark(10000); // mark the position

                return;
            }
        }
    }

    /** Skips empty lines in the stream.
     * @param stream The stream possibly containing empty lines.
     * @throws IOException Thrown if a problem occurs.
     */
    static public void skipEmptyLines(BufferedInputStream stream)
        throws IOException {
        byte[] b = new byte[BUF_LEN]; // the byte buffer
        stream.mark(BUF_LEN + 2); // mark the beginning

        while (stream.available() > 0) { // check that there are still something to read

            int num = stream.read(b); // read bytes from the file to the byte buffer

            int i = 0;

            while ((i < num) && ((b[i] == CARR) || (b[i] == NL))) {
                i++;
            }

            stream.reset();
            stream.skip(i);

            if (i < num) {
                stream.mark(10000);

                return;
            } else {
                stream.mark(BUF_LEN);
            }
        }
    }
}

/** This class lists all the files defined in the constructor.
 * The definitions can be in three forms.
 * 1. absolute file (/tmp/test.txt)
 * 2. absolute path (/tmp)
 * 3. a wildcard file (/tmp/*.txt)
 *
 * In case 1. only the file is returned.
 * In case 2. all files in the directory are returned
 * In case 3. all the files in the directory tmp having
 * the .txt ending are returned.
 *
 * The returning means the return of the getListing method.
 */
class DirectoryList {
    static Logger logger = Logger.getLogger(DirectoryList.class.getName());
    List files = null;

    /** Creates a new instance of DirectoryList
     * @param path The file definition, see class description above.
     * @throws Exception Thrown if the path was invalid
     */
    public DirectoryList(String path) throws IOException {
        // splits the absolute? filename from the wildcard
        String[] parts = path.split("\\*");

        // accept only one wildcard, so file is of the form /tmp/*.x or /tmp/a.x
        if ((parts.length < 1) || (parts.length > 2)) {
            return;
        }

        // check whether the first and only part is a file or directory
        if (parts.length == 1) {
            // open the directory or file
            File fileOrDir = new File(parts[0]);

            // if the path given was fully specified filename
            if (fileOrDir.isFile()) {
                // set the file as the only member in the vector and finish
                files = new Vector();
                files.add(fileOrDir);

                return;
            }

            // the path defined a directory, so get all files
            File[] fileDirArray;

            // list the files and dirs inside
            fileDirArray = fileOrDir.listFiles();

            if (fileDirArray == null) {
                logger.error("No files found matching " + path);
                throw new IOException("No files found matching " + path);
            }

            // get the array containing all the files and directories
            Iterator filesAndDirs = Arrays.asList(fileDirArray).iterator();

            files = new Vector();

            // add all the files to the files list and finish
            while (filesAndDirs.hasNext()) {
                File nextFile = (File) filesAndDirs.next();

                if (nextFile.isFile()) {
                    files.add(nextFile);
                }
            }

            return;
        } else {
            // this is a directory+ending combination
            files = new Vector();

            // get all the files matching the definition.
            FileEndingIterator iterator = new FileEndingIterator(parts[0], parts[1]);

            while (iterator.hasNext()) {
                files.add(iterator.next());
            }

            return;
        }
    }

    /** Used to get the file listing, the list of files matching
     * the definition in constructor.
     * @return Returns the list of files matching the definition
     * given in the constructor.
     */
    public List getListing() {
        return files;
    }
}

/**
 * @deprecated  This class does not expose the necessary information. Use
 * PKIStore instead.
 *
 * Implementation of a AC trust store for use with VOMS. The store
 * keeps an in-memory cache of issuer certificates, which can be
 * refreshed periodically.
 *
 * @author mulmo
 * @author Vincenzo Ciaschini
 */
public final class BasicVOMSTrustStore implements ACTrustStore {
    static Logger log = Logger.getLogger(BasicVOMSTrustStore.class);
    public static final String DEFAULT_TRUST_STORE_LISTING = PKIStore.DEFAULT_VOMSDIR;
    String trustedDirList = null;
    private Hashtable issuerCerts = new Hashtable();
    private long refreshPeriod = -1;
    private String path = null;
    private Timer theTimer = null;

    /**
     * Creates a default VOMS trust store. Equivalent to<br>
     * <code>new BasicVOMSTrustStore(DEFAULT_TRUST_STORE_LISTING, 300000);</code>
     */
    public BasicVOMSTrustStore() {
        this(DEFAULT_TRUST_STORE_LISTING, 300000);
    }

    /**
     * Creates and manages an in-memory cache of VOMS issuers by
     * periodically scanning a directory containing the trusted
     * issuers.
     *
     * If <code>refreshPeriod</code> is 0, it never refreshes.<br>
     *
     * @param trustedDirList directory listing containing trusted VOMS certs
     * @param refreshPeriod  refresh period in milliseconds
     *
     * @see DirectoryList
     */
    public BasicVOMSTrustStore(String trustedDirList, long refreshPeriod) {
        super();

        if (refreshPeriod < 0) {
            throw new IllegalArgumentException("refreshPeriod is negative");
        }

        List l;

        try {
            l = new DirectoryList(trustedDirList).getListing();
        } catch (IOException e) {
            l = null;
        }

        if ((l == null) || l.isEmpty()) {
            String msg = "VOMS trust anchors " + trustedDirList + " does not appear to exist";
            log.fatal(msg);
            throw new IllegalArgumentException(msg);
        }

        this.trustedDirList = trustedDirList;
        this.refreshPeriod = refreshPeriod;

        if (refreshPeriod == 0) {
            refresh();
        }

        if (refreshPeriod > 0) {
            theTimer = new Timer(true);
            theTimer.scheduleAtFixedRate(new Refreshener(), 0, refreshPeriod);
        }
    }

    public String getDirList() {
        return trustedDirList;
    }


    public void stopRefresh() {
        if (theTimer != null)
            theTimer.cancel();
        theTimer = null;
    }

    /**
     * Refreshes the in-memory cache of trusted signer certificates.
     */
    public void refresh() {
        try {
            if (log.isDebugEnabled()) {
                log.debug("Refreshing in-memory VOMS issuer cache from " + trustedDirList);
            }

            Hashtable newTable = new Hashtable();
            List certs = new FileCertReader().readCerts(trustedDirList);

            for (Iterator i = certs.iterator(); i.hasNext();) {
                X509Certificate cert = (X509Certificate) i.next();
                Object key = cert.getSubjectX500Principal();
                List l = (List) newTable.get(key);

                if (l == null) {
                    l = new Vector();
                }

                l.add(cert);
                newTable.put(key, l);
            }

            issuerCerts = newTable;

            if (log.isDebugEnabled()) {
                log.debug("Refreshing of in-memory VOMS issuer cache done. Read " + certs.size() + " certs");
            }
        } catch (Exception e) {
            log.error("Unexpected error while refreshing in-memory VOMS issuer cache from " + trustedDirList + " : " +
                e.getMessage());
        }
    }

    /* (non-Javadoc)
     * @see org.glite.security.voms.ac.ACTrustStore#getAACandidate(org.glite.security.voms.ac.AttributeCertificate)
     */
    public X509Certificate[] getAACandidate(X500Principal issuer) {
        if (refreshPeriod < 0) {
            refresh();
        }

        List l = (List) issuerCerts.get(issuer);

        if (l != null) {
            return (X509Certificate[]) l.toArray(new X509Certificate[l.size()]);
        }

        return null;
    }

    private class Refreshener extends TimerTask {
        public void run() {
            refresh();
        }
    }
}
