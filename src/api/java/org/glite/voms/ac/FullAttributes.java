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
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERSequence;

/**
 * This class represents the GenericAttributes extension which may be found
 * in the AC.
 *
 * @author Vincenzo Ciaschini
 */
public class FullAttributes implements DEREncodable {
    private List l;

    /**
     * Empty contructor
     */
    public FullAttributes() {
        l = new Vector();
    }

    /**
     * Creates a FullAttributes object from a sequence.
     *
     * @param seq the Sequence
     *
     * @throws IllegalArgumentException if there are parsing problems.
     */
    public FullAttributes(ASN1Sequence seq) {
        l = new Vector();
        if (seq.size() != 1)
            throw new IllegalArgumentException("Encoding error in FullAttributes");

        seq = (ASN1Sequence) seq.getObjectAt(0);
        for (Enumeration e = seq.getObjects(); e.hasMoreElements(); ) {
            AttributeHolder holder = new AttributeHolder((ASN1Sequence)e.nextElement());
            l.add(holder);
        }
    }

    /**
     * Static variant of the constructor.
     *
     * @see #FullAttributes(ASN1Sequence seq)
     */
    public static FullAttributes getInstance(ASN1Sequence seq) {
        return new FullAttributes(seq);
    }

    /**
     * Returns a list of the AttributeHolders.
     *
     * @return the list or null if none was there.
     */
    public List getAttributeHolders() {
        return l;
    }

    /**
     * Makes a DERObject representation.
     *
     * @return the DERObject
     */
    public DERObject getDERObject() {
        ASN1EncodableVector v2 = new ASN1EncodableVector();

        for (ListIterator li = l.listIterator(); li.hasNext(); ) {
            AttributeHolder holder = (AttributeHolder)li.next();
            v2.add(holder);
        }

        ASN1Sequence seq = (ASN1Sequence) new DERSequence(v2);
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(seq);

        return new DERSequence(v);
    }
}
