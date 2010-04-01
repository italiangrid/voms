/*********************************************************************
 *
 * Authors: 
 *      Andrea Ceccanti - andrea.ceccanti@cnaf.infn.it 
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

import java.io.IOException;
import java.io.InputStream;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.log4j.Logger;
import org.xml.sax.SAXException;


/**
 * 
 * This class implements the XML parsing of responses produced by VOMS servers.
 * 
 * @author Andrea Ceccanti
 *
 */
public class VOMSParser {

    private static Logger log = Logger.getLogger( VOMSParser.class );
    
    protected DocumentBuilder docBuilder;
    
    private VOMSParser(){
        
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
            
            throw new VOMSException(e.getMessage(),e);
        }
    }
    
    /**
     * 
     * Parses a voms response reading from a given input stream.
     * @param is the input stream.
     * @return a {@link VOMSResponse} object that represents the parsed response.
     */
    public VOMSResponse parseResponse(InputStream is){
        
        
        try {
        
            return new VOMSResponse(docBuilder.parse( is ));
            
        } catch ( SAXException e ) {
            
            log.error( "Error parsing voms server response:" +e.getMessage());
            
            if (log.isDebugEnabled())
                log.error(e.getMessage(),e);
            
            throw new VOMSException(e);
            
        } catch ( IOException e ) {
            
            log.error( "I/O error reading voms server response:" +e.getMessage());
            if (log.isDebugEnabled())
                log.error(e.getMessage(),e);
            
            throw new VOMSException(e);
        }
        
    }
    
    /**
     * @return a new VOMSParser instance.
     */
    public static VOMSParser instance(){
        return new VOMSParser();
    }
}
