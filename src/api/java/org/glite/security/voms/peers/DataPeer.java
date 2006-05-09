package org.glite.security.voms.peers;

public final class DataPeer {
    public String group;
    public String role;
    public String cap;

    public DataPeer(String a, String b, String c) {
        group = a;
        role = b;
        cap = c;
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
