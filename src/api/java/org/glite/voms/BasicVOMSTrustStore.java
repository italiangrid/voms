/*********************************************************************
 *
 * Authors: Vincenzo Ciaschini - Vincenzo.Ciaschini@cnaf.infn.it 
 *          Valerio Venturi    - Valerio.Venturi@cnaf.infn.it
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
import java.security.cert.X509Certificate;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.Timer;
import java.util.TimerTask;
import java.util.Vector;

import javax.security.auth.x500.X500Principal;

import org.apache.log4j.Logger;
import org.glite.voms.ac.ACTrustStore;


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
     * @see org.glite.voms.ac.ACTrustStore#getAACandidate(org.glite.voms.ac.AttributeCertificate)
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
