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

import java.util.Enumeration;
import java.util.List;
import java.util.ListIterator;
import java.util.Vector;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;


/**
 * This calss represents an Attribute Holder object.
 *
 * @author Vincenzo Ciaschini
 */
public class AttributeHolder implements DEREncodable {
    private List l;
    private GeneralNames grantor;

    /**
     * Empty constructor.
     */
    public AttributeHolder() {
        l = null;
        grantor = null;
    }

    /**
     * Creates an AttributeHolder object from a Sequence.
     *
     * @param seq the Sequence
     *
     * @throws IllegalArgumentException if there are parsing problems.
     */
    public AttributeHolder(ASN1Sequence seq) {
        l = new Vector();
        grantor = null;

        if (seq.size() != 2)
            throw new IllegalArgumentException("Encoding error in AttributeHolder");

        if ((seq.getObjectAt(0) instanceof ASN1Sequence) &&
            (seq.getObjectAt(1) instanceof ASN1Sequence)) {
            grantor = GeneralNames.getInstance(seq.getObjectAt(0));
            seq = (ASN1Sequence) seq.getObjectAt(1);
            for (Enumeration e = seq.getObjects(); e.hasMoreElements(); ) {
                GenericAttribute att = new GenericAttribute((ASN1Sequence)e.nextElement());
                l.add(att);
            }
        }
        else
            throw new IllegalArgumentException("Encoding error in AttributeHolder");
    }
    /**
     * Static variant of the constructor.
     *
     * @see #AttributeHolder(ASN1Sequence seq)
     */
    public static AttributeHolder getInstance(ASN1Sequence seq) {
        return new AttributeHolder(seq);
    }

    /**
     * Gets the Grantor of these attributes.
     *
     * @return the grantor.
     */
    public String getGrantor() {
        ASN1Sequence seq = ASN1Sequence.getInstance(grantor.getDERObject());
        GeneralName  name  = GeneralName.getInstance(seq.getObjectAt(0));
        return DERIA5String.getInstance(name.getName()).getString();
    }

    /**
     *
     * Gets a list of Generic Attributes.
     *
     * @return the list or null if none was loaded.
     */
    public List getAttributes() {
        return l;
    }

    /**
     * Makes a DERObject representation.
     *
     * @return the DERObject
     */
    public DERObject getDERObject() {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(grantor);
        
        ASN1EncodableVector v2 = new ASN1EncodableVector();

        for (ListIterator li = l.listIterator(); li.hasNext(); ) {
            GenericAttribute att = (GenericAttribute)li.next();
            v2.add(att);
        }
        ASN1Sequence seq = (ASN1Sequence) new DERSequence(v2);

        v.add(seq);

        return new DERSequence(v);
    }
}
