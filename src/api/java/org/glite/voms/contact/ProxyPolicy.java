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
package org.glite.voms.contact;

import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DEROctetString;

public class ProxyPolicy implements DEREncodable {
    private DERObjectIdentifier oid;
    private DEROctetString      policy;

    public static final DERObjectIdentifier IMPERSONATION = new DERObjectIdentifier("1.3.6.1.5.5.7.21.1");
    public static final DERObjectIdentifier INDEPENDENT = new DERObjectIdentifier("1.3.6.1.5.5.7.21.2");
    public static final DERObjectIdentifier LIMITED = new DERObjectIdentifier("1.3.6.1.4.1.3536.1.1.1.9");

    public ProxyPolicy(DERObjectIdentifier oid) {
        this.oid = oid;
        this.policy = null;
    }

    public ProxyPolicy(DERObjectIdentifier oid, String policy) {
        this.oid = oid;
        this.policy = new DEROctetString(policy.getBytes());
    }

    public ProxyPolicy(String oid, String policy) {
        this.oid = new DERObjectIdentifier(oid);
        this.policy= new DEROctetString(policy.getBytes());
    }

    public ProxyPolicy(String oid) {
        this.oid = new DERObjectIdentifier(oid);
        this.policy= null;
    }

    public DERObject getDERObject() {
        ASN1EncodableVector vec = new ASN1EncodableVector();

        vec.add(oid);
        if (policy != null)
            vec.add(policy);

        return new DERSequence(vec);
    }

    public ProxyPolicy(ASN1Sequence seq) {
        this.oid = (DERObjectIdentifier)seq.getObjectAt(0);
        if (seq.size() > 1) {
            DEREncodable obj = seq.getObjectAt(1);
            if (obj instanceof DERTaggedObject) {
                obj = ((DERTaggedObject)obj).getObject();
            }
            this.policy = (DEROctetString)obj;
        }
    }
};

