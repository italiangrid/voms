/*********************************************************************
 *
 * Authors:
 *      Vincenzo Ciaschini - vincenzo.ciaschini@cnaf.infn.it
 *
 * Copyright (c) 2006 INFN-CNAF on behalf of the EGEE project.
 *
 * For license conditions see LICENSE
 *
 * Parts of this code may be based upon or even include verbatim pieces,
 * originally written by other people, in which case the original header
 * follows.
 *
 *********************************************************************/
package org.glite.voms.contact;

import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DEREncodableVector;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.ASN1Sequence;

public class MyProxyCertInfo implements DEREncodable {

    private int pathLen;
    private ProxyPolicy policy;
    private int version;

    public MyProxyCertInfo(ProxyPolicy policy, int version) {
        this.policy = policy;
        this.pathLen = -1;
        this.version = version;
    }

    public MyProxyCertInfo(int pathLenConstraint,
                           ProxyPolicy policy, int version) {
        this.policy = policy;
        this.pathLen = pathLenConstraint;
        this.version = version;
    }

    public int getPathLenConstraint() {
        return pathLen;
    }

    public ProxyPolicy getProxyPolicy() {
        return policy;
    }

    public MyProxyCertInfo(ASN1Sequence seq) {
        if (seq.size() == 1) {
            // Only one element.  Must be a ProxyPolicy
            this.pathLen = -1;
            this.policy = new ProxyPolicy((ASN1Sequence)(seq.getObjectAt(0)));
        }
        else {
            // Two elements.  Which one is the first?
            DEREncodable obj = seq.getObjectAt(0);
            if (obj instanceof DERInteger) {
                this.pathLen = ((DERInteger)obj).getValue().intValue();
                this.policy  = new ProxyPolicy((ASN1Sequence)(seq.getObjectAt(0)));
                this.version = VOMSProxyBuilder.GT3_PROXY;
            }
            else {
                this.policy  = new ProxyPolicy((ASN1Sequence)(seq.getObjectAt(0)));
                this.pathLen = ((DERInteger)obj).getValue().intValue();
                this.version = VOMSProxyBuilder.GT4_PROXY;
            }
        }
    }

    public DERObject getDERObject() {
        DEREncodableVector vec = new DEREncodableVector();

        switch(version) {
        case VOMSProxyBuilder.GT3_PROXY:
            if (this.pathLen != -1) {
                vec.add(new DERInteger(this.pathLen));
            }
            vec.add(this.policy.getDERObject());
            break;

        case VOMSProxyBuilder.GT4_PROXY:
            vec.add(this.policy.getDERObject());
            if (this.pathLen != -1) {
                vec.add(new DERInteger(this.pathLen));
            }
            break;

        default:
            break;
        }
        return new DERSequence(vec);
    }
}
