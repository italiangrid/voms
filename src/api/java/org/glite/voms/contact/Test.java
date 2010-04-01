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
package org.glite.voms.contact;



import java.io.IOException;
import java.security.GeneralSecurityException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;

import javax.xml.transform.TransformerException;

import org.apache.log4j.PropertyConfigurator;
import org.glite.voms.contact.VOMSProxyConstants;
import org.ietf.jgss.GSSException;


public class Test {


    public static void main( String[] args ) throws TransformerException, GSSException, IOException, GeneralSecurityException, ParseException {
        
        PropertyConfigurator.configure( "./src/api/java/log4j.properties" );
        
        VOMSRequestOptions options = new VOMSRequestOptions();
        VOMSRequestOptions vo8Options = new VOMSRequestOptions();
        
        vo8Options.setVoName( "vo8" );
        options.setVoName( "test_oci" );
        options.addFQAN( "/test_oci/Role=CiccioPaglia" );
        options.setOrdering( "/test_oci/Role=CiccioPaglia,/test_oci" );
        
        List optLists = new ArrayList();
        
        optLists.add( options );
        optLists.add( vo8Options );
        
        VOMSProxyInit proxyInit = VOMSProxyInit.instance();
        
        UserCredentials proxy = proxyInit.getVomsProxy( optLists );

    }
}
