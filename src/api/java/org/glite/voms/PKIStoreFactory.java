/*********************************************************************
 *
 * Authors: Vincenzo Ciaschini - Vincenzo.Ciaschini@cnaf.infn.it
 *
 * Copyright (c) 2002-2009 INFN-CNAF on behalf of the EU DataGrid
 * and EGEE I, II and III
 * For license conditions see LICENSE file or
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 *
 * Parts of this code may be based upon or even include verbatim pieces,
 * originally written by other people, in which case the original header
 * follows.
 *
 *********************************************************************/


package org.glite.voms;

import java.io.IOException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.util.Hashtable;
import org.apache.log4j.Logger;
import org.glite.voms.PKIStore;

class Parameters {
    String dir;
    int type;
    boolean aggressive;
    boolean timer;

    Parameters(String s, int t, boolean a, boolean ti) {
        dir        = s;
        type       = t;
        aggressive = a;
        timer      = ti;
    }
}


public class PKIStoreFactory {
    private static Hashtable stores = null;
    private static final int HASHCAPACITY = 75;

    private static Logger logger = Logger.getLogger(PKIStoreFactory.class.getName());

    public synchronized static PKIStore getStore(String dir, int type, boolean aggressive, boolean timer) throws IOException, CertificateException, CRLException {
        if (stores == null)
            stores = new Hashtable(HASHCAPACITY);

        Parameters param = new Parameters(dir, type, aggressive, timer);

        PKIStore result = null;

        result = (PKIStore)stores.get(param);

        if (result == null) {
            result = new PKIStore(dir, type, aggressive, timer);
            stores.put(param, result);
        }
        else {
            result.addInstance();
        }

        return result;
    }

    public synchronized static PKIStore getStore(String dir, int type, boolean aggressive) throws IOException, CertificateException, CRLException {
        return PKIStoreFactory.getStore(dir, type, aggressive, true);
    }

    public synchronized static PKIStore getStore(String dir, int type) throws IOException, CertificateException, CRLException {
        return PKIStoreFactory.getStore(dir, type, true, true);
    }

    public synchronized static PKIStore getStore(int type) throws IOException, CertificateException, CRLException {
        return PKIStoreFactory.getStore(null, type, true, true);
    }

    public synchronized static PKIStore getStore() {
        return new PKIStore();
    }
}
