/*
 * Copyright (c) Members of the EGEE Collaboration. 2004-2010.
 * See http://www.eu-egee.org/partners/ for details on the copyright holders.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import java.util.Collection;
import java.util.Vector;

import org.glite.voms.*;
import org.glite.voms.contact.*;
import org.glite.voms.ac.*;

class contactvoms5 {
    public static void main(String[] args) {
        UserCredentials c = UserCredentials.instance(args[0], args[1]);
        VOMSProxyInit vpi = VOMSProxyInit.instance(c);
        vpi.setProxyType(VOMSProxyBuilder.GT2_PROXY);
        vpi.setProxyOutputFile(args[2]);
        VOMSRequestOptions o = new VOMSRequestOptions();
        o.setVoName("voms1");
        o.addFQAN("all");
        o.setLifetime(10000000);
        Collection col = new Vector();
        col.add(o);
        vpi.getVomsProxy(col);
        System.out.println("DO WARNINGS");
        if (vpi.hasWarnings()) {
            VOMSWarningMessage[] msgs = vpi.getWarnings();
            for (int i = 0 ; i < msgs.length; i++)
                System.out.println(msgs[i].toString());
        }
    }
}
