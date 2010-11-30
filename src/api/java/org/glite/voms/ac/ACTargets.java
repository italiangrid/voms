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
 * The intent of this class is to represent the ACTargets extension which
 * may be present in the AC.
 *
 * @author Vincenzo Ciaschini
 */
public class ACTargets implements DEREncodable {
    private List l;
    private List parsed;

    /**
     * Empty constructor.
     */
    public ACTargets() {
        l = new Vector();
        parsed = new Vector();
    }

    /**
     * Creates an ACTargets from a sequence.
     *
     * @param seq the sequence.
     *
     * @throws IllegalArgumentException if there are parsing errors.
     */
    public ACTargets(ASN1Sequence seq) {
        l = new Vector();
        parsed = new Vector();

        for (Enumeration e = seq.getObjects(); e.hasMoreElements(); ) {
            ACTarget targ = new ACTarget((ASN1Sequence)e.nextElement());
            l.add(targ);
            parsed.add(targ.toString());
        }
    }

    /**
     * Static variant of the constructor.
     *
     * @see #ACTargets(ASN1Sequence seq)
     */
    public static ACTargets getInstance(ASN1Sequence seq) {
        return new ACTargets(seq);
    }

    /**
     * Manually add a target.
     *
     * @param s the target.
     */
    public void addTarget(String s) {
        ACTarget trg = new ACTarget();
        trg.setName(s);
        l.add(trg);
    }

    /**
     * Manually add a target.
     *
     * @param act the target.
     *
     * @see org.glite.voms.ac.ACTarget
     */
    public void AddTarget(ACTarget act) {
        l.add(act);
    }

    /**
     * Gets the list of targets.
     *
     * @return a List containing the targets, expressed as String.
     */
    public List getTargets() {
        return parsed;
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
            ACTarget c = (ACTarget)li.next();
            v.add(c);
        }
        return new DERSequence(v);
    }
}
