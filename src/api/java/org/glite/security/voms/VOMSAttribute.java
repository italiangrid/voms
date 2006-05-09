/*
 * Copyright (c) Members of the EGEE Collaboration. 2004.
 * See http://eu-egee.org/partners/ for details on the copyright holders.
 * For license conditions see the license file or http://eu-egee.org/license.html
 */

package org.glite.security.voms;

import org.apache.log4j.Logger;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x509.GeneralName;

import javax.security.cert.X509Certificate;
import javax.security.auth.x500.X500Principal;

import org.glite.security.voms.ac.AttributeCertificate;
import org.glite.security.voms.ac.IetfAttrSyntax;

import java.util.SimpleTimeZone;
import java.util.Iterator;
import java.util.List;
import java.util.Vector;
import java.util.Date;

import java.text.ParseException;
import java.text.SimpleDateFormat;

import org.glite.security.voms.peers.VomsPeer;

/**
 * Representation of the authorization information (VO, server address
 * and list of Fully Qualified Attribute Names, or FQANs) contained in
 * a VOMS attribute certificate.
 *
 * @author Olle Mulmo
 */
public class VOMSAttribute {
    private static Logger logger = Logger.getLogger(VOMSAttribute.class);

    /**
     * The ASN.1 object identifier for VOMS attributes
     */
    public static final String VOMS_ATTR_OID = "1.3.6.1.4.1.8005.100.100.4";
    private AttributeCertificate myAC;
    private String myHostPort;
    private String myVo;
    private Vector myStringList = new Vector();
    private Vector myFQANs = new Vector();
    private VomsPeer v = null;

    public VOMSAttribute(VomsPeer p) {
        v = p;
    }

    public VOMSAttribute(AttributeCertificate ac, VomsPeer p) {
        this(ac);
        v = p;
    }
    /**
     * Returns the signature of the AC.
     * @return the byte representation of the AC signature.
     */

    public byte[] getSignature() {
        if (v == null)
            throw new IllegalArgumentException("VOMSAttribute structure not properly initialized.");
        return v.signature;
    }

    /**
     * Returns the serial number of the AC.
     * @return the serial number of the AC.
     */
    public String getSerial() {
        if (v == null)
            throw new IllegalArgumentException("VOMSAttribute structure not properly initialized.");
        return v.serial;
    }

    private static Date convert(String t) throws ParseException {
        SimpleDateFormat dateF;

        // BouncyCastle change the output of getTime() and instead
        // introduced a new method getDate() method... better make
        // sure we stay compatible 

        if (t.indexOf("GMT") > 0) {
            dateF = new SimpleDateFormat("yyyyMMddHHmmssz");
        } else {
            dateF = new SimpleDateFormat("yyyyMMddHHmmss'Z'");
            dateF.setTimeZone(new SimpleTimeZone(0, "Z"));
        }

        return dateF.parse(t);
    }

    /**
     * Returns the end date of the AC validity.
     * @return the end Date.
     */
    public Date getNotAfter() throws ParseException {
        if (v == null)
            throw new IllegalArgumentException("VOMSAttribute structure not properly initialized.");
        return convert(v.date2);
    }

    /**
     * Return the start date of the AC validity.
     * @return the start Date.
     */
    public Date getNotBefore() throws ParseException {
        if (v == null)
            throw new IllegalArgumentException("VOMSAttribute structure not properly initialized.");
        return convert(v.date1);
    }

    /**
     * Checks if the AC was valid at the provided timestamp.
     * @param date if <code>null</code>, current time is used
     * @return true if the AC was valid at the time in question.
     */
    public boolean validAt(Date date) {
        if (date == null) {
            date = new Date();
        }

        try {
            return (getNotAfter()).after(date) && (getNotBefore()).before(date);
        } catch (ParseException e) {
            throw new IllegalArgumentException("Invalid validity encoding in Attribute Certificate");
        }
    }

    /**
     * Returns an OpenSSL-style representation of the AC issuer.
     * @return the AC issuer.
     */
    public String getIssuer() {
        if (v == null)
            throw new IllegalArgumentException("VOMSAttribute structure not properly initialized.");
        return v.server;
    }

    /**
     * Returns an OpenSSL-style representation of the AC holder.
     * @return the AC holder.
     */
    public String getHolder() {
        if (v == null)
            throw new IllegalArgumentException("VOMSAttribute structure not properly initialized.");
        return v.user;
    }

    public boolean isValid() {
        if (v == null)
            throw new IllegalArgumentException("VOMSAttribute structure not properly initialized.");
        return validAt(new Date());
    }

    /**
     * Checks the given X509 certificate to see if it is the holder of the AC.
     * @param the X509 certificate to check.
     * @return true if the give certificate is the holder of the AC.
     */
    public boolean isHolder(X509Certificate cert) {
        if (v == null)
            throw new IllegalArgumentException("VOMSAttribute structure not properly initialized.");

        X500Principal p = new X500Principal(v.holder);

        return cert.getSubjectDN().toString() == p.toString();
    }

    /**
     * Checks the given X509 certificate to see if it is the issuer of the AC.
     * @param the X509 certificate to check.
     * @return true if the give certificate is the issuer of the AC.
     */
    public boolean isIssuer(X509Certificate cert) {
        if (v == null)
            throw new IllegalArgumentException("VOMSAttribute structure not properly initialized.");

        X500Principal p = new X500Principal(v.issuer);

        return cert.getSubjectDN().toString() == p.toString();
    }

    /**
     * Parses the contents of an attribute certificate.<br>
     * <b>NOTE:</b> Cryptographic signatures, time stamps etc. will <b>not</b> be checked.
     *
     * @param ac the attribute certificate to parse for VOMS attributes
     */
    public VOMSAttribute(AttributeCertificate ac) {
        if (ac == null) {
            throw new IllegalArgumentException("VOMSAttribute: AttributeCertificate is NULL");
        }

        myAC = ac;

        List l = ac.getAttributes(VOMS_ATTR_OID);

        if ((l == null) || (l.size() == 0)) {
            return;
        }

        try {
            for (Iterator i = l.iterator(); i.hasNext();) {
                ASN1Sequence seq = (ASN1Sequence) i.next();
                IetfAttrSyntax attr = new IetfAttrSyntax(seq);

                // policyAuthority is on the format <vo>/<host>:<port>
                String url = ((DERIA5String) GeneralName.getInstance(((ASN1Sequence) attr.getPolicyAuthority()
                                                                                         .getDERObject()).getObjectAt(0))
                                                        .getName()).getString();
                int idx = url.indexOf("://");

                if ((idx < 0) || (idx == (url.length() - 1))) {
                    throw new IllegalArgumentException("Bad encoding of VOMS policyAuthority : [" + url + "]");
                }

                myVo = url.substring(0, idx);
                myHostPort = url.substring(idx + 3);

                if (attr.getValueType() != IetfAttrSyntax.VALUE_OCTETS) {
                    throw new IllegalArgumentException(
                        "VOMS attribute values are not encoded as octet strings, policyAuthority = " + url);
                }

                for (Iterator j = attr.getValues().iterator(); j.hasNext();) {
                    String fqan = new String(((ASN1OctetString) j.next()).getOctets());
                    FQAN f = new FQAN(fqan);

                    // maybe requiring that the attributes start with vo is too much?
                    if (!myStringList.contains(fqan) && (fqan.startsWith("/" + myVo + "/") || fqan.equals("/" + myVo))) {
                        myStringList.add(fqan);
                        myFQANs.add(f);
                    }
                }
            }
        } catch (IllegalArgumentException ie) {
            throw ie;
        } catch (Exception e) {
            throw new IllegalArgumentException("Badly encoded VOMS extension in AC issued by " +
                ac.getIssuer().getName());
        }
    }

    /**
     * @deprecated Direct access to the Attribute Certificate is going to
     *             be removed. Use the getXXX methods in this same classe
     *             instead.
     *
     * @return The AttributeCertificate containing the VOMS information
     */
    public AttributeCertificate getAC() {
        return myAC;
    }

    /**
     * @return List of String of the VOMS fully qualified
     * attributes names (FQANs):<br>
     * <code>vo[/group[/group2...]][/Role=[role]][/Capability=capability]</code>
     */
    public List getFullyQualifiedAttributes() {
        return myStringList;
    }

    /**
     * @return List of FQAN of the VOMS fully qualified
     * attributes names (FQANs)
     * @see #FQAN
     */
    public List getListOfFQAN() {
        return myFQANs;
    }

    /**
     * Returns the address of the issuing VOMS server, on the form <code>&lt;host&gt;:&lt;port&gt;</code>
     * @return String
     */
    public String getHostPort() {
        return myHostPort;
    }

    /**
     * Returns the VO name
     * @return
     */
    public String getVO() {
        return myVo;
    }

    public String toString() {
        return "VO      :" + myVo + "\n" + "HostPort:" + myHostPort + "\n" + "FQANs   :" + myFQANs;
    }
}
