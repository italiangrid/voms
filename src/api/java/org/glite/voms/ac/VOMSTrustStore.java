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
package org.glite.voms.ac;

import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import org.glite.voms.LSCFile;


/**
 * @author Vincenzo Ciaschini
 */
public interface VOMSTrustStore {
    /**
     * Returns the LSCFile corresponding to the VO and Host specified.
     *
     * @param voName the name of the VO.
     * @param hostName the name of the issuing host.
     *
     * @return the LSCfile, or null if none is found.
     */
    public LSCFile getLSC(String voName, String hostName);

    /**
     * Returns candidates to the role of signer of an AC with he given
     * issuer and of the give VO.
     *
     * @param issuer the DN of the signer.
     * @param voName the VO to which he signer belongs.
     *
     * @return an array of issuer candidates, or null if none is found.
     */
    public X509Certificate[] getAACandidate(X500Principal issuer, String voName);

    /**
     * Stops refreshing the store.
     *
     * This method MUST be called prior to disposing of the store.
     */
    public void stopRefresh();
}

