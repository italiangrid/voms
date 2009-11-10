import java.util.List;

import org.glite.voms.*;
import org.glite.voms.contact.*;
import org.glite.voms.ac.*;

class contactvoms2 {
    public static void main(String[] args) {
        UserCredentials c = UserCredentials.instance(args[0], args[1]);
        VOMSProxyInit vpi = VOMSProxyInit.instance(c);
        vpi.setProxyType(VOMSProxyBuilder.GT2_PROXY);
        VOMSRequestOptions o = new VOMSRequestOptions();
        o.setVoName("voms1");
        o.addFQAN("/voms1");
        AttributeCertificate ac = vpi.getVomsAC(o);
        if (ac != null) {
            List fqans = ac.getFullyQualifiedAttributes();
            if (fqans != null) {
                for (int i =0; i < fqans.size(); i++)
                    System.out.println("FQAN:"+(String)(fqans.get(i)));
            }
        }
    }
}
