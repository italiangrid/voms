/*********************************************************************
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

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DEREnumerated;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;


public class ObjectDigestInfo implements DEREncodable {
    DEREnumerated digestedObjectType;
    DERObjectIdentifier otherObjectTypeID;
    AlgorithmIdentifier digestAlgorithm;
    DERBitString objectDigest;

    public ObjectDigestInfo(ASN1Sequence seq) {
        digestedObjectType = DEREnumerated.getInstance((DERTaggedObject) seq.getObjectAt(0));

        int offset = 0;

        if (seq.size() == 4) {
            otherObjectTypeID = DERObjectIdentifier.getInstance(seq.getObjectAt(1));
            offset++;
        }

        digestAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(1 + offset));

        objectDigest = new DERBitString(seq.getObjectAt(2 + offset));
    }

    public DEREnumerated getDigestedObjectType() {
        return digestedObjectType;
    }

    public DERObjectIdentifier getOtherObjectTypeID() {
        return otherObjectTypeID;
    }

    public AlgorithmIdentifier getDigestAlgorithm() {
        return digestAlgorithm;
    }

    public DERBitString getObjectDigest() {
        return objectDigest;
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     *  ObjectDigestInfo ::= SEQUENCE {
     *       digestedObjectType  ENUMERATED {
     *               publicKey            (0),
     *               publicKeyCert        (1),
     *               otherObjectTypes     (2) },
     *                       -- otherObjectTypes MUST NOT
     *                       -- be used in this profile
     *       otherObjectTypeID   OBJECT IDENTIFIER OPTIONAL,
     *       digestAlgorithm     AlgorithmIdentifier,
     *       objectDigest        BIT STRING
     *  }
     * </pre>
     */
    public DERObject getDERObject() {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(digestedObjectType);

        if (otherObjectTypeID != null) {
            v.add(otherObjectTypeID);
        }

        v.add(digestAlgorithm);
        v.add(objectDigest);

        return new DERSequence(v);
    }
}
