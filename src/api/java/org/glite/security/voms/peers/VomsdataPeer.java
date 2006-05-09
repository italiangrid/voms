package org.glite.security.voms.peers;
import java.security.cert.X509Certificate;

public final class VomsdataPeer {
    private long d;

    public int error;
    
    native public  boolean LoadSystemContacts(String dir);
    native public  boolean LoadUserContacts(String dir);
    native public  ContactDataPeer[] FindByAlias(String alias);
    native public  ContactDataPeer[] FindByVO(String vo);
    native public  void Order(String att);
    native public  void ResetOrder();
    native public  void AddTarget(String target);
    native public  String[] ListTargets();
    native public  void ResetTargets();
    native public  String ServerErrors();
    native private boolean RetrieveReal(byte[] cert, byte[][] chain, int how);
    native public  boolean Contact(String host, int port, String subject, String command);
    native public  void SetVerificationType(int type);
    native public  void SetLifetime(int life);
    native public  boolean Import(String buffer);
    native private byte[] ExportReal();
    native private VomsPeer DefaultDataReal();
    native public  String ErrorMessage();
    native public  int ErrorCode();

    native public synchronized void destroy();

    private native long create(String dir1, String dir2);
    private native long create(VomsdataPeer org);

    public static final int RECURSIVE = 1;

    public VomsdataPeer(String dir1, String dir2) {
        d = create(dir1, dir2);
    }

    public VomsdataPeer() {
        d = create("","");
    }

    public VomsdataPeer(VomsdataPeer orig) {
        d = create(orig);
    }

    protected void finalize() {
        destroy();
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

    private VomsPeer[] data;

    public VomsPeer GetData(int i) {
        return data[i];
    }

    public int GetDataLength() {
        return data.length;
    }

    public boolean Retrieve(X509Certificate cert, X509Certificate[] chain, int how) {
        try {
            byte[] c = cert.getEncoded();
            byte[][] ch = new byte[chain.length][];

            for (int i = 0; i < chain.length; i++)
                ch[i] = chain[i].getEncoded();

            return RetrieveReal(c, ch, how);
        }
        catch(java.security.cert.CertificateEncodingException e) {
            return false;
        }
    }

    public boolean Export(String buffer) {
        byte[] coded = ExportReal();

        if (coded != null) {
            buffer = new String(coded);
            return true;
        }
        return false;
    }

    public boolean DefaultData(VomsPeer data) {
        if (data == null)
            return false;

        VomsPeer p = DefaultDataReal();

        if (p != null) {
            data.voname    = p.voname;
            data.version   = p.version;
            data.siglen    = p.siglen;
            data.signature = p.signature;
            data.user      = p.user;
            data.userca    = p.userca;
            data.server    = p.server;
            data.serverca  = p.serverca;
            data.date1     = p.date1;
            data.date2     = p.date2;
            data.type      = p.type;
            data.std       = p.std;
            data.fqan      = p.fqan;
            data.serial    = p.serial;

            return true;
        }
        else
            return false;
    }
}
