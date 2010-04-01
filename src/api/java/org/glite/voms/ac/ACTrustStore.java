/*********************************************************************
 *
 * Authors: Olle Mulmo
 *          Vincenzo Ciaschini - Vincenzo.Ciaschini@cnaf.infn.it 
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
/*
 * Copyright (c) Members of the EGEE Collaboration. 2004.
 * See http://eu-egee.org/partners/ for details on the copyright holders.
 * For license conditions see the license file or http://eu-egee.org/license.html
 */

package org.glite.voms.ac;

import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;


/**
 * @deprecated This does not expose the necessary information.
 *
 * @author mulmo
 */
public interface ACTrustStore {
    /**
     * Returns an array of issuer candidates, by performing a name
     * comparison of the AC's issuer and the subject names of the
     * certificates in the trust store.
     * <br>
     * <b>NOTE:</b> No actual verification or validation of signature
     * takes place in this function.
     *
     * @param issuer the principal to find an issuer for.
     * If <code>null</code>, all known AAs will be returned.
     * @return an array of issuer candidates, or <code>null</code> in
     * case of an error.
     */
    public X509Certificate[] getAACandidate(X500Principal issuer);
}
