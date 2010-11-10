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

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.Security;
import java.util.Enumeration;
import java.util.List;
import java.util.ListIterator;
import java.util.Vector;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.jce.provider.X509CertificateObject;

/**
 * This class represents the ACCerts extension which may be present in the AC.
 *
 * @author Vincenzo Ciaschini.
 */
public class ACCerts implements DEREncodable {
    List l;

    /**
     * Creates an empty ACCerts object.
     */
    public ACCerts() {
        l = new Vector();
    }

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * Creates an ACCerts starting from a sequence.
     *
     * @param seq the Sequence.
     *
     * @throws IllegalArgumentException if Certificates are not supported
     * or if there is an encoding error.
     */
    public ACCerts(ASN1Sequence seq) {
        l = new Vector();
        seq = (ASN1Sequence) seq.getObjectAt(0);
        CertificateFactory cf = null;
        try {
            cf = CertificateFactory.getInstance("X.509", "BC");
        }
        catch (NoSuchProviderException e) {
            throw new ExceptionInInitializerError("Cannot find BouncyCastle provider: " + e.getMessage());
        }
        catch (CertificateException e) {
            throw new ExceptionInInitializerError("X.509 Certificates unsupported. " + e.getMessage());
        }
        catch (Exception ex) {
            throw new IllegalArgumentException("Error in setting up ACCerts reader. " + ex.getMessage());
        }

        for (Enumeration e = seq.getObjects(); e.hasMoreElements();){
            Object o = e.nextElement();

            if (o instanceof DERSequence) {
                ASN1Sequence s = ASN1Sequence.getInstance(o);
                byte[] data = null;
                try {
                      data = new X509CertificateObject(X509CertificateStructure.getInstance(s)).getEncoded();
                      l.add((X509Certificate)cf.generateCertificate(new ByteArrayInputStream(data)));
                }
                catch(Exception ex) {
                    throw new IllegalArgumentException("Error in encoding ACCerts. " + ex.getMessage());
                }
            }
            else
                throw new IllegalArgumentException("Incorrect encoding for ACCerts");
        }
    }

    /**
     * static variant of the constructor.
     *
     * @see #ACCerts(ASN1Sequence seq)
     */
    public static ACCerts getInstance(ASN1Sequence seq) {
        return new ACCerts(seq);
    }

    /**
     * Manually adds a certificate to the list.
     *
     * @param cert The certificate to add.
     */
    public void addCert(X509CertificateStructure cert) {
        l.add(cert);
    }

    /**
     * Gets the certificates.
     *
     * @return the list of certificates.
     */
    public List getCerts() {
        return l;
    }

    /**
     * Makes a DERObject representation.
     *
     * @return the DERObject
     */
    public DERObject getDERObject() {
        ASN1EncodableVector v = new ASN1EncodableVector();

        ListIterator li = l.listIterator();
        while (li.hasNext()) {
            X509CertificateStructure x509 = (X509CertificateStructure)li.next();
            v.add(x509);
        }
        return new DERSequence(v);
    }
}
