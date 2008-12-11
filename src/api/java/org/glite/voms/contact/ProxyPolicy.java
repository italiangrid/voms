package org.glite.voms.contact;

import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DEREncodableVector;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DEROctetString;

public class ProxyPolicy implements DEREncodable {
    private DERObjectIdentifier oid;
    private DEROctetString      policy;

    public static final DERObjectIdentifier IMPERSONATION = new DERObjectIdentifier("1.3.6.1.5.5.7.21.1");
    public static final DERObjectIdentifier INDEPENDENT = new DERObjectIdentifier("1.3.6.1.5.5.7.21.2");
    public static final DERObjectIdentifier LIMITED = new DERObjectIdentifier("1.3.6.1.4.1.3536.1.1.1.9");

    public ProxyPolicy(DERObjectIdentifier oid) {
        this.oid = oid;
        this.policy = null;
    }

    public ProxyPolicy(DERObjectIdentifier oid, String policy) {
        this.oid = oid;
        this.policy = new DEROctetString(policy.getBytes());
    }

    public ProxyPolicy(String oid, String policy) {
        this.oid = new DERObjectIdentifier(oid);
        this.policy= new DEROctetString(policy.getBytes());
    }

    public ProxyPolicy(String oid) {
        this.oid = new DERObjectIdentifier(oid);
        this.policy= null;
    }

    public DERObject getDERObject() {
        DEREncodableVector vec = new DEREncodableVector();

        vec.add(oid);
        if (policy != null)
            vec.add(policy);

        return new DERSequence(vec);
    }

    public ProxyPolicy(ASN1Sequence seq) {
        this.oid = (DERObjectIdentifier)seq.getObjectAt(0);
        if (seq.size() > 1) {
            DEREncodable obj = seq.getObjectAt(1);
            if (obj instanceof DERTaggedObject) {
                obj = ((DERTaggedObject)obj).getObject();
            }
            this.policy = (DEROctetString)obj;
        }
    }
};

