import org.glite.voms.*;
import org.glite.voms.contact.*;

class basicvalidation {
    public static void main(String[] args) {
        UserCredentials c = UserCredentials.instance(args[0], args[0]);
        VOMSValidator v = new VOMSValidator(c.getUserChain());
        v.validate();
        int size = v.getAllFullyQualifiedAttributes().length;
        System.out.println("Size = " + size);
        System.exit(size == 0 ? 1 : 0);
    }
}
