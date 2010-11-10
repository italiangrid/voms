/*********************************************************************
 *
 * Authors:
 *      Vincenzo Ciaschini - vincenzo.ciaschini@cnaf.infn.it
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
package org.glite.voms.contact;

import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Object;
import java.io.IOException;
import java.io.ByteArrayInputStream;
import org.bouncycastle.asn1.ASN1InputStream;

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

    private void setFromSeq(ASN1Sequence seq) {
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
    public MyProxyCertInfo(ASN1Sequence seq) {
        setFromSeq(seq);
    }

    public MyProxyCertInfo(byte[] payload) {
        DERObject derObj = null;
        try {
            ByteArrayInputStream inStream = new ByteArrayInputStream(payload);
            ASN1InputStream derInputStream = new ASN1InputStream(inStream);
            derObj = derInputStream.readObject();
        } catch (IOException e) {
            throw new IllegalArgumentException("Unable to convert byte array: " + 
                                                   e.getMessage());
        }
        if (derObj instanceof ASN1Sequence) {
            setFromSeq((ASN1Sequence)derObj);
        }
        else
            throw new IllegalArgumentException("Unable to convert byte array");
    }

    public DERObject getDERObject() {
        ASN1EncodableVector vec = new ASN1EncodableVector();

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
