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

import java.math.BigInteger;
import java.security.PrivateKey;
import java.util.Date;
import java.util.List;
import java.util.Vector;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;


/**
 *
 * <pre>
 *     AttributeCertificateInfo ::= SEQUENCE {
 *          version              AttCertVersion -- version is v2,
 *          holder               Holder,
 *          issuer               AttCertIssuer,
 *          signature            AlgorithmIdentifier,
 *          serialNumber         CertificateSerialNumber,
 *          attrCertValidityPeriod   AttCertValidityPeriod,
 *          attributes           SEQUENCE OF Attribute,
 *          issuerUniqueID       UniqueIdentifier OPTIONAL,
 *          extensions           Extensions OPTIONAL
 *     }
 *
 *     AttCertVersion ::= INTEGER { v2(1) }
 * </pre>
 * @author mulmo
 */
public class ACGenerator {
    X500Principal issuer;
    X500Principal holderIssuer;
    BigInteger holderSerial;
    Date notAfter;
    Date notBefore;
    Vector attributes;
    Vector extensions;

    /**
     * @param oid
     * @param policyAuthority
     * @param value
     */
    public void addAttribute(String oid, String policyAuthority, String value) {
    }

    /**
     * @param oid
     * @param policyAuthority
     * @param values
     */
    public void addAttributes(String oid, String policyAuthority, List values) {
    }

    /**
     * @param vector
     */
    public void setExtensions(Vector vector) {
        extensions = vector;
    }

    /**
     * @param principal
     */
    public void setHolderIssuer(X500Principal principal) {
        holderIssuer = principal;
    }

    /**
     * @param integer
     */
    public void setHolderSerial(BigInteger integer) {
        holderSerial = integer;
    }

    /**
     * @param principal
     */
    public void setIssuer(X500Principal principal) {
        issuer = principal;
    }

    /**
     * @param date
     */
    public void setNotAfter(Date date) {
        notAfter = (Date)date.clone();
    }

    /**
     * @param date
     */
    public void setNotBefore(Date date) {
        notBefore = (Date)date.clone();
    }

    public AttributeCertificateInfo generateACInfo() {
        if ((issuer == null) || (holderIssuer == null) || (holderSerial == null) || (notAfter == null) ||
                (notBefore == null)) {
            throw new IllegalArgumentException("All mandatory components are not present");
        }

        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new DERInteger(1));
        v.add(new Holder(holderIssuer, holderSerial));
        v.add(new AttCertIssuer(new V2Form(Util.x500nameToGeneralNames(issuer))));
        v.add(new AlgorithmIdentifier("1.2.840.113549.1.1.5")); // sha1WithRSA
        v.add(new DERInteger(1));

        return null;
    }

    public void sign(PrivateKey key) {
    }
}
