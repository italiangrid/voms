import org.glite.voms.*;
import org.glite.voms.contact.*;

import java.security.cert.X509Certificate;

class onlycertvalidation {
    private static X509Certificate[] userChain;

    public static void main(String[] args) {
        try {
            userChain = PKIUtils.loadCertificates(args[0]);
            PKIVerifier pv = new PKIVerifier();
            if ( pv.verify(userChain))
                System.out.println("VERIFIED!");
            else
                System.out.println("NOT VERIFIED!");
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }
}
