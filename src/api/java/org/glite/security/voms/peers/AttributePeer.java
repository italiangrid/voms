package org.glite.security.voms.peers;

public final class AttributePeer {
    public String name;
    public String value;
    public String qualifier;

    public AttributePeer(String n, String v, String q) {
        name = n;
        value = v;
        qualifier = q;
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
