package org.glite.security.voms.peers;

public final class AttributeListPeer {
    public String grantor;
    public AttributePeer[] attributes;

    public AttributeListPeer(String g, AttributePeer[] a) {
        grantor = g;
        attributes = a;
    }

    native static private synchronized void initializer();
    static {
        try {
            System.loadLibrary("vomsapi");
        }
        catch(UnsatisfiedLinkError ie) {
            System.loadLibrary("vomsapi_nog");
        }
        initializer();
    }
}
