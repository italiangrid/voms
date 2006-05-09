/*
 * Copyright (c) Members of the EGEE Collaboration. 2004.
 * See http://eu-egee.org/partners/ for details on the copyright holders.
 * For license conditions see the license file or http://eu-egee.org/license.html
 */

package org.glite.security.voms.ac;

import org.apache.log4j.Logger;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERConstructedSet;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERInputStream;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AttCertValidityPeriod;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.X509Extensions;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

import java.security.PublicKey;
import java.security.Signature;

import java.text.ParseException;
import java.text.SimpleDateFormat;

import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.SimpleTimeZone;
import java.util.Vector;

import javax.security.auth.x500.X500Principal;


/**
 * A shadow implementation of the non-working BouncyCastle implementation
 * of X.509 Attribute Certificates
 *
 * @author Joni Hahkala, Olle Mulmo
 */
public class AttributeCertificate implements DEREncodable {
    protected static Logger logger = Logger.getLogger(AttributeCertificate.class);
    AttributeCertificateInfo acInfo;
    AlgorithmIdentifier signatureAlgorithm;
    DERBitString signatureValue;

    public AttributeCertificate(ASN1Sequence seq) throws IOException {
        acInfo = new AttributeCertificateInfo((ASN1Sequence) seq.getObjectAt(0));
        signatureAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));
        signatureValue = (DERBitString) seq.getObjectAt(2);
    }

    /**
     * Create an Attribute Certificate from a input stream containing
     * DER-encoded data
     *
     * @param in
     * @return
     * @throws IOException
     */
    public static AttributeCertificate getInstance(InputStream in)
        throws IOException {
        DERInputStream dIn = new DERInputStream(in);
        ASN1Sequence seq = (ASN1Sequence) dIn.readObject();

        return new AttributeCertificate(seq);
    }

    public AttributeCertificateInfo getAcinfo() {
        return acInfo;
    }

    /**
     *
     * @see org.glite.security.voms.ac.AttributeCertificateInfo#getAttributes()
     */
    public ASN1Sequence getAttributes() {
        if (acInfo == null) {
            return null;
        }

        return acInfo.getAttributes();
    }

    /**
     * Returns a list of the attributes matching the provided OID.
     * @param oid Object Identifier, on the form "1.2.3.4"
     * @return List of ASN.1 objects representing the OID type in question
     */
    public List getAttributes(String oid) {
        if (oid == null) {
            return Collections.EMPTY_LIST;
        }

        ASN1Sequence seq = getAttributes();

        if ((seq == null) || (seq.size() == 0)) {
            return Collections.EMPTY_LIST;
        }

        Vector v = new Vector();

        for (Enumeration e = seq.getObjects(); e.hasMoreElements();) {
            ASN1Sequence attribute = (ASN1Sequence) e.nextElement();

            if (oid.equals(((DERObjectIdentifier) attribute.getObjectAt(0)).getId())) {
                DERConstructedSet set = (DERConstructedSet) attribute.getObjectAt(1);

                for (Enumeration s = set.getObjects(); s.hasMoreElements();) {
                    v.add(s.nextElement());
                }
            }
        }

        return v;
    }

    public X509Extensions getExtensions() {
        return (acInfo == null) ? null : acInfo.getExtensions();
    }

    public X500Principal getIssuer() {
        if (acInfo == null) {
            return null;
        }

        if (acInfo.getIssuer() == null) {
            return null;
        }

        ASN1Sequence seq = (ASN1Sequence) acInfo.getIssuer().getIssuerName().getDERObject();

        for (Enumeration e = seq.getObjects(); e.hasMoreElements();) {
            GeneralName gn = GeneralName.getInstance((ASN1TaggedObject) e.nextElement());

            if (gn.getTagNo() == 4) {
                return Util.generalNameToX500Name(gn);
            }
        }

        return null;
    }

    public Holder getHolder() {
        return (acInfo == null) ? null : acInfo.getHolder();
    }

    private static Date getDate(DERGeneralizedTime time)
        throws ParseException {
        SimpleDateFormat dateF;

        // BouncyCastle change the output of getTime() and instead
        // introduced a new method getDate() method... better make
        // sure we stay compatible 
        String t = time.getTime();

        if (t.indexOf("GMT") > 0) {
            dateF = new SimpleDateFormat("yyyyMMddHHmmssz");
        } else {
            dateF = new SimpleDateFormat("yyyyMMddHHmmss'Z'");
            dateF.setTimeZone(new SimpleTimeZone(0, "Z"));
        }

        return dateF.parse(time.getTime());
    }

    public Date getNotAfter() throws ParseException {
        return getDate(acInfo.getAttrCertValidityPeriod().getNotAfterTime());
    }

    public Date getNotBefore() throws ParseException {
        return getDate(acInfo.getAttrCertValidityPeriod().getNotBeforeTime());
    }

    public AlgorithmIdentifier getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public DERBitString getSignatureValue() {
        return signatureValue;
    }

    /**
     * Checks if the AC was valid at the provided timestamp.
     * @param date if <code>null</code>, current time is used
     * @return true if the AC was valid at the time in question.
     */
    public boolean validAt(Date date) {
        AttCertValidityPeriod validity = acInfo.getAttrCertValidityPeriod();

        if (date == null) {
            date = new Date();
        }

        try {
            return getDate(validity.getNotAfterTime()).after(date) &&
            getDate(validity.getNotBeforeTime()).before(date);
        } catch (ParseException e) {
            throw new IllegalArgumentException("Invalid validity encoding in Attribute Certificate");
        }
    }

    /**
     * Synonym for <code>validAt(null)</code>
     * @return true if currently valid
     */
    public boolean isValid() {
        return validAt(new Date());
    }

    /**
     * Verifies the signature of the AC using the provided signature key
     *
     * @param key The (RSA) public key to verify the signature with
     * @return <code>true</code> if success, <code>false</code> otherwise
     */
    public boolean verify(PublicKey key) {
        String error = null;

        try {
            ByteArrayOutputStream b = new ByteArrayOutputStream();
            new DEROutputStream(b).writeObject(acInfo);

            Signature sig = Signature.getInstance(signatureAlgorithm.getObjectId().getId());
            sig.initVerify(key);
            sig.update(b.toByteArray());

            return sig.verify(signatureValue.getBytes());
        } catch (Exception e) {
            if (logger.isDebugEnabled()) {
                logger.debug("Error verifying signature of AC issued by " + getIssuer().getName() + " : " +
                    e.getMessage());
            }
        }

        return false;
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     *  AttributeCertificate ::= SEQUENCE {
     *       acinfo               AttributeCertificateInfo,
     *       signatureAlgorithm   AlgorithmIdentifier,
     *       signatureValue       BIT STRING
     *  }
     * </pre>
     */
    public DERObject getDERObject() {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(acInfo);
        v.add(signatureAlgorithm);
        v.add(signatureValue);

        return new DERSequence(v);
    }
}
