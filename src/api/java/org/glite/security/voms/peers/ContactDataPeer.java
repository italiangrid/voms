package org.glite.security.voms.peers;

public final class ContactDataPeer {
    public String nick;
    public String host;
    public String contact;
    public int port;
    public int version;
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
    public ContactDataPeer(String n, String h, String c, int p, int v) {
        nick = n;
        host = h;
        contact = c;
        port = p;
        version = v;
    }
}
