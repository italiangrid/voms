/*********************************************************************
 *
 * Authors: Olle Mulmo
 *
 * Copyright (c) 2004-2009 INFN-CNAF on behalf of the EU DataGrid
 * and EGEE I, II and III
 * For license conditions see LICENSE file or
 * http://www.apache.org/licenses/LICENSE-2.0.txt
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
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuerSerial;


/**
 * @author mulmo
 */
public class V2Form implements DEREncodable {
    GeneralNames issuerName;
    IssuerSerial baseCertificateID;
    ObjectDigestInfo objectDigestInfo;

    public V2Form(GeneralNames issuerName) {
        this.issuerName = issuerName;
    }

    public V2Form(ASN1Sequence seq) {
        int n = 0;

        if (seq.getObjectAt(0) instanceof ASN1Sequence) {
            issuerName = new GeneralNames((ASN1Sequence) seq.getObjectAt(0));
            n++;
        }

        for (; n < seq.size(); n++) {
            ASN1TaggedObject tObj = (ASN1TaggedObject) seq.getObjectAt(n);

            switch (tObj.getTagNo()) {
            case 0:
                baseCertificateID = new IssuerSerial((ASN1Sequence) tObj.getObject());

                break;

            case 1:
                objectDigestInfo = new ObjectDigestInfo((ASN1Sequence) tObj.getObject());

                break;

            default:
                throw new IllegalArgumentException("Bad tag " + tObj.getTagNo() + " in V2Form");
            }
        }
    }

    public GeneralNames getIssuerName() {
        return issuerName;
    }

    public IssuerSerial getBaseCertificateID() {
        return baseCertificateID;
    }

    public ObjectDigestInfo getObjectDigestInfo() {
        return objectDigestInfo;
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     *  V2Form ::= SEQUENCE {
     *       issuerName            GeneralNames  OPTIONAL,
     *       baseCertificateID     [0] IssuerSerial  OPTIONAL,
     *       objectDigestInfo      [1] ObjectDigestInfo  OPTIONAL
     *         -- issuerName MUST be present in this profile
     *         -- baseCertificateID and objectDigestInfo MUST NOT
     *         -- be present in this profile
     *  }
     * </pre>
     */
    public DERObject getDERObject() {
        ASN1EncodableVector v = new ASN1EncodableVector();

        if (issuerName != null) {
            // IMPLICIT encoding of GeneralNames ... gosh, how I hate ASN.1 sometimes.
            v.add(((ASN1Sequence) issuerName.getDERObject()).getObjectAt(0));
        }

        if (baseCertificateID != null) {
            v.add(new DERTaggedObject(0, baseCertificateID));
        }

        if (objectDigestInfo != null) {
            v.add(new DERTaggedObject(1, objectDigestInfo));
        }

        return new DERSequence(v);
    }
}
