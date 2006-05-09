/*
 * Copyright (c) Members of the EGEE Collaboration. 2004.
 * See http://eu-egee.org/partners/ for details on the copyright holders.
 * For license conditions see the license file or http://eu-egee.org/license.html
 */

package org.glite.security.voms.ac;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DEREncodableVector;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AttCertValidityPeriod;
import org.bouncycastle.asn1.x509.X509Extensions;


/**
 * Shadow implementation of AttributeCertificateInfo from
 * BouncyCastle
 *
 * @author Joni Hahkala, Olle Mulmo
 */
public class AttributeCertificateInfo implements DEREncodable {
    DERInteger version;
    Holder holder;
    AttCertIssuer issuer;
    AlgorithmIdentifier signature;
    DERInteger serialNumber;
    AttCertValidityPeriod attrCertValidityPeriod;
    ASN1Sequence attributes;
    DERBitString issuerUniqueID;
    X509Extensions extensions;
    boolean badVomsEncoding = false;

    public AttributeCertificateInfo(ASN1Sequence seq) {
        version = (DERInteger) seq.getObjectAt(0);
        holder = new Holder((ASN1Sequence) seq.getObjectAt(1));
        issuer = new AttCertIssuer(seq.getObjectAt(2));
        signature = new AlgorithmIdentifier((ASN1Sequence) seq.getObjectAt(3));
        serialNumber = (DERInteger) seq.getObjectAt(4);

        // VOMS has encoding problems of attCertValidity (uses PrivateKeyUsagePeriod syntax instead)
        ASN1Sequence s2 = (ASN1Sequence) seq.getObjectAt(5);
        ASN1Sequence s3 = s2;

        if (s2.getObjectAt(0) instanceof ASN1TaggedObject) {
            badVomsEncoding = true;

            DEREncodableVector v = new DEREncodableVector();

            for (int i = 0; i < 2; i++) {
                byte[] bb = ((DEROctetString) ((ASN1TaggedObject) s2.getObjectAt(i)).getObject()).getOctets();
                v.add(new DERGeneralizedTime(new String(bb)));
            }

            s3 = (ASN1Sequence) new DERSequence(v);
        }

        attrCertValidityPeriod = new AttCertValidityPeriod(s3);
        attributes = (ASN1Sequence) seq.getObjectAt(6);

        // check if the following two can be detected better!!! 
        // for example, is it possible to have only the extensions? how to detect this?
        if (seq.size() > 8) {
            issuerUniqueID = new DERBitString(seq.getObjectAt(7));
            extensions = new X509Extensions((ASN1Sequence) seq.getObjectAt(8));
        } else if (seq.size() > 7) {
            extensions = new X509Extensions((ASN1Sequence) seq.getObjectAt(7));
        }
    }

    public static AttributeCertificateInfo getInstance(ASN1Sequence seq) {
        return new AttributeCertificateInfo(seq);
    }

    public DERInteger getAttCertVersion() {
        return version;
    }

    public Holder getHolder() {
        return holder;
    }

    public AttCertIssuer getIssuer() {
        return issuer;
    }

    public AlgorithmIdentifier getSignature() {
        return signature;
    }

    public DERInteger getSerialNumber() {
        return serialNumber;
    }

    public AttCertValidityPeriod getAttrCertValidityPeriod() {
        return attrCertValidityPeriod;
    }

    public ASN1Sequence getAttributes() {
        return attributes;
    }

    public DERBitString getIssuerUniqueID() {
        return issuerUniqueID;
    }

    public X509Extensions getExtensions() {
        return extensions;
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     *
     * <pre>
     *
     *
     *
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
     *
     *
     *
     * </pre>
     */
    public DERObject getDERObject() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(version);
        v.add(holder);
        v.add(issuer);
        v.add(signature);
        v.add(serialNumber);

        if (!badVomsEncoding) {
            v.add(attrCertValidityPeriod);
        } else {
            DEREncodableVector v2 = new DEREncodableVector();
            v2.add(new DERTaggedObject(false, 0,
                    new DEROctetString((attrCertValidityPeriod.getNotBeforeTime().getTime().substring(0, 14) + "Z").getBytes())));
            v2.add(new DERTaggedObject(false, 1,
                    new DEROctetString((attrCertValidityPeriod.getNotAfterTime().getTime().substring(0, 14) + "Z").getBytes())));
            v.add(new DERSequence(v2));
        }

        v.add(attributes);

        if (issuerUniqueID != null) {
            v.add(issuerUniqueID);
        }

        if (extensions != null) {
            v.add(extensions);
        }

        return new DERSequence(v);
    }
}
