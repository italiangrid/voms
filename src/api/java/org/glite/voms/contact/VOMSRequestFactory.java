/*********************************************************************
 *
 * Authors: 
 *      Andrea Ceccanti    - andrea.ceccanti@cnaf.infn.it 
 *      Vincenzo Ciaschini - vincenzo.ciaschini@cnaf.infn.it
 *          
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
 *
 * Parts of this code may be based upon or even include verbatim pieces,
 * originally written by other people, in which case the original header
 * follows.
 *
 *********************************************************************/
package org.glite.voms.contact;

import java.util.Iterator;
import java.util.List;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.DocumentFragment;
import org.w3c.dom.Element;



/**
 * 
 * This class builds VOMS XML requests starting from {@link VOMSRequestOptions} objects.
 *  
 * @author Andrea Ceccanti
 * @author Vincenzo Ciaschini
 *
 */
public class VOMSRequestFactory {
    
    private static Logger log = Logger.getLogger( VOMSRequestFactory.class );
    private static VOMSRequestFactory instance = null;
    
    private String orderString;
    private String targetString;
    private long lifetime = 0;
    
    protected DocumentBuilder docBuilder;
    
    public static VOMSRequestFactory instance(){
        if (instance == null)
            instance = new VOMSRequestFactory();
        
        return instance;
        
    }
    
    private VOMSRequestFactory(){
        
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setIgnoringComments( true );
        factory.setNamespaceAware( false );
        factory.setValidating( false );

        try {
            docBuilder = factory.newDocumentBuilder();
        } catch ( ParserConfigurationException e ) {
            
            log.fatal( "Error configuring DOM document builder." );
            
            if (log.isDebugEnabled()){
                log.debug( e.getMessage(), e );
            }
            
            throw new VOMSException(e);
        }
    }
        
    public long getLifetime() {
    
        return lifetime;
    }
    
    public void setLifetime( long lifetime ) {
    
        this.lifetime = lifetime;
    }



    
    public String getOrderString() {
    
        return orderString;
    }



    
    public void setOrderString( String orderString ) {
    
        this.orderString = orderString;
    }



    
    public String getTargetString() {
    
        return targetString;
    }



    
    public void setTargetString( String targetString ) {
    
        this.targetString = targetString;
    }
    
    private void setOptionsForRequest(VOMSRequestFragment fragment){
        
        if (orderString != null && orderString != "")
            fragment.buildOrderElement( orderString );
        
        if (targetString != null && targetString != "")
            fragment.buildTargetsElement( targetString );
        
               
        fragment.buildLifetime( lifetime );
    }
    
    private void loadOptions(VOMSRequestOptions options){
        
        lifetime = options.getLifetime();
        setOrderString( options.getOrdering() );
        setTargetString( options.getTargetsAsString() );
        
    }

    public String buildRESTRequest(VOMSRequestOptions options) {
        loadOptions(options);

        if (options.isRequestList()) {
            /* handle list requests */

            return "/generate-ac?fqans=all";
        }

        StringBuilder request = new StringBuilder();

        request.append("/generate-ac?fqans=");

        if (options.getRequestedFQANs().isEmpty()){
            
            if (options.getVoName() == null)
                throw new VOMSException("No vo name specified for AC retrieval.");
            String voName = options.getVoName();
            
            if (!voName.startsWith( "/"))
                voName = "/"+voName;

            request.append(voName);
        }
        else {
            List FQANs = options.getRequestedFQANs();
            Iterator i = FQANs.iterator();
            boolean first = true;

            while ( i.hasNext()) {
                if (!first)
                    request.append(",");
                request.append((String)i.next());
                first = false;
            }
        }
        if (targetString != null && targetString.trim().length() != 0) {
            request.append("&targets=");
            request.append(targetString);
        }

        if (orderString != null && orderString.trim().length() != 0) {
            request.append("&order=");
            request.append(orderString);
        }

        request.append("&lifetime=");
        request.append(lifetime);
        log.debug("Generated request: " + request.toString());
        return request.toString();
    }

    public Document buildRequest(VOMSRequestOptions options){
        
        loadOptions( options );
        
        Document request = docBuilder.newDocument();
        VOMSRequestFragment frag = new VOMSRequestFragment(request);
        
        if (options.isRequestList()) {
            frag.listCommand();
            setOptionsForRequest(frag);
            request.appendChild(frag.getFragment());
            return request;
        }

        if (options.getRequestedFQANs().isEmpty()){
            
            if (options.getVoName() == null)
                throw new VOMSException("No vo name specified for AC retrieval.");
            
            String voName = options.getVoName();
            
            if (!voName.startsWith( "/"))
                voName = "/"+voName;
                
            frag.groupCommand( voName );
            setOptionsForRequest( frag );
            
            request.appendChild( frag.getFragment() );
            return request;
        }
               
        Iterator fqanIter = options.getRequestedFQANs().iterator();
        frag.buildBase64();
        frag.buildVersion();
        while (fqanIter.hasNext()){
            
            String FQAN = (String)fqanIter.next();
            
            if (FQAN.equals("all")) {
                frag.allCommand();
            }
            else if (PathNamingScheme.isGroup( FQAN )){
            
                frag.groupCommand( FQAN );
                
            }else if (PathNamingScheme.isRole( FQAN )){
                
                frag.roleCommand( PathNamingScheme.getRoleName( FQAN ));
                
            }else if (PathNamingScheme.isQualifiedRole( FQAN )){
                
                frag.mappingCommand( PathNamingScheme.getGroupName( FQAN ), PathNamingScheme.getRoleName( FQAN ));
            }
        }
        
        setOptionsForRequest( frag );
        
        request.appendChild( frag.getFragment() );
        return request;
    }
    
    
    
    
 
}


class VOMSRequestFragment{
    
    private Document doc;
    
    DocumentFragment fragment;
    Element root;
    Element command;
    Element order;
    Element targets;
    Element lifetime;
    Element base64;
    Element version;
    
    public VOMSRequestFragment(Document doc){
        
        this.doc = doc;
        
        fragment = doc.createDocumentFragment();
        buildRootElement();    
    }
    
    protected void buildRootElement(){
        
        root = doc.createElement( "voms" );
        fragment.appendChild( root );
        
    }
    
    private void appendTextChild(Element e, String text){
        
        e.appendChild( doc.createTextNode( text ) );
    }
    
    
    private String buildCompatibleOrderString(String s){
        
        String[] FQANs = s.split(",");
        
        if (FQANs.length == 0)
            return "";
        
        
        for (int i=0; i < FQANs.length; i++){
            if (PathNamingScheme.isQualifiedRole( FQANs[i] ))
                FQANs[i] = PathNamingScheme.toOldQualifiedRoleSyntax( FQANs[i] );
        }
        
        return StringUtils.join( FQANs, ",");        
    }

    void buildCommandElement(String cmdString){
        
        command = doc.createElement( "command");
        appendTextChild( command, cmdString);
        root.appendChild( command );           
    }
    
    void buildOrderElement(String orderString){
        
        order = doc.createElement( "order" );
        
        // Temporary compatibility hack
        appendTextChild( order,buildCompatibleOrderString( orderString ));
        
        root.appendChild( order );
    }
    
    void buildTargetsElement(String targetString){
        
        targets = doc.createElement( "targets" );
        appendTextChild( targets, targetString);
        root.appendChild( targets );
        
    }
    
    void buildLifetime(long lifetime){
        buildLifetime( Long.toString( lifetime ) );
    }
    
    void buildLifetime(String lifetimeString){
        
        lifetime = doc.createElement( "lifetime" );
        appendTextChild( lifetime, lifetimeString);
        root.appendChild( lifetime );
    }

    void buildBase64() {
        base64 = doc.createElement( "base64");
        appendTextChild(base64, "1");
        root.appendChild(base64);
    }

    void buildVersion() {
        version = doc.createElement("version");
        appendTextChild(version, "4");
        root.appendChild(version);
    }

    public DocumentFragment getFragment() {
    
        return fragment;
    }
    
    
    public void groupCommand(String groupName){
        buildCommandElement( "G"+groupName );
    }
    
    public void roleCommand(String roleName){
        
        buildCommandElement( "R"+roleName );
   
    }
    
    public void mappingCommand(String groupName, String roleName){
        
        buildCommandElement( "B"+groupName+":"+roleName );
        
    }
    
    public void allCommand(){
        
        buildCommandElement( "A" );
    }

    public void listCommand() {
        buildCommandElement( "N" );
    }
}
