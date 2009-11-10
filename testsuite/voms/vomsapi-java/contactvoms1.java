import org.glite.voms.*;
import org.glite.voms.contact.*;

class contactvoms1 {
    public static void main(String[] args) {
        UserCredentials c = UserCredentials.instance(args[0], args[1]);
        VOMSProxyInit vpi = VOMSProxyInit.instance(c);
        vpi.setProxyOutputFile(args[2]);
        vpi.setProxyType(VOMSProxyBuilder.GT2_PROXY);
        VOMSRequestOptions o = new VOMSRequestOptions();
        o.doRequestList();
        o.setVoName("voms1");
        System.out.println(vpi.getVomsData(o));
    }
}
