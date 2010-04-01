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
        if (s == null)
            dir        = "";
        else
            dir = s;
        type       = t;
        aggressive = a;
        timer      = ti;
    }

    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }

        if (anObject instanceof Parameters) {
            Parameters p = (Parameters) anObject;
            if (dir == null)
                return p.dir == null && aggressive == p.aggressive && timer == p.timer && type == p.type;
            else
                return aggressive == p.aggressive && timer == p.timer && type == p.type && dir.equals(p.dir);
        }
        return false;
    }

    public int hashCode() {
        int hash = 1;
        hash = hash * 31 + (dir == null ? 0 : dir.hashCode());
        hash = hash * 31 + type;
        hash = hash * 31 + (aggressive ? 1 : 0);
        return hash * 31 + (timer ? 1 : 0);
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("Params: ");
        sb.append("[dir:");
        sb.append(dir);
        sb.append("], [type:");
        sb.append(type);
        sb.append("], [agressive:");
        sb.append(aggressive);
        sb.append("], [timer:");
        sb.append(timer);
        sb.append("]");
        return sb.toString();
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
