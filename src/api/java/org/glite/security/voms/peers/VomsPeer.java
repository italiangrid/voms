package org.glite.security.voms.peers;

public final class VomsPeer {
    public  int version;
    public  int siglen;
    public  byte[] signature;
    public  String user;
    public  String userca;
    public  String server;
    public  String serverca;
    public  String voname;
    public  String date1;
    public  String date2;
    public  int type;
    public  DataPeer[] std;
    public  String custom;
    public  String[] fqan;
    public  String serial;
    public  byte[] holder;
    public  byte[] issuer;
    public  String uri;
    private long d;

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
