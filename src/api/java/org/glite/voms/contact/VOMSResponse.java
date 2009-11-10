/*********************************************************************
 *
 * Authors: 
 *      Andrea Ceccanti    - andrea.ceccanti@cnaf.infn.it 
 *      Vincenzo Ciaschini - vincenzo.ciaschini@cnaf.infn.it
 *          
 * Copyright (c) 2006-2009 INFN-CNAF on behalf of the EGEE I, II and III
 * For license conditions see LICENSE file or
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 *
 * Parts of this code may be based upon or even include verbatim pieces,
 * originally written by other people, in which case the original header
 * follows.
 *
 *********************************************************************/
package org.glite.voms.contact;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

/**
 * 
 * This class is used to parse and represent VOMS server responses.
 *  
 * @author Andrea Ceccanti
 *
 */
public class VOMSResponse {

    private static int ERROR_OFFSET = 1000;

    protected Document xmlResponse;

    public boolean hasErrors() {
        // errors imply that no AC were created
        return ((xmlResponse.getElementsByTagName( "item" ).getLength() != 0) &&
                (xmlResponse.getElementsByTagName( "ac" ).getLength() == 0));
    }

    public boolean hasWarnings() {
        // warnings imply that ACs were created
        return ((xmlResponse.getElementsByTagName( "item" ).getLength() != 0) &&
                (xmlResponse.getElementsByTagName( "ac" ).getLength() != 0));
    }
    /**
     * 
     * Extracts the AC from the VOMS response.
     * @return an array of bytes containing the AC. 
     */
    public byte[] getAC() {

        Element acElement = (Element) xmlResponse.getElementsByTagName( "ac" )
                .item( 0 );
        
        return VOMSDecoder.decode( acElement.getFirstChild().getNodeValue()); 

    }

    /**
     * 
     * Extracts the textual data from the VOMS response.
     * @return an array of bytes containing the data. 
     */

    public byte[] getData() {
        Element acElement = (Element) xmlResponse.getElementsByTagName( "bitstr" )
                .item( 0 );
        
        return VOMSDecoder.decode( acElement.getFirstChild().getNodeValue()); 


    }

    /**
     * Extracts the version from the VOMS response.
     * 
     * @return an integer containing the AC.
     */
    public int getVersion() {
        Element versionElement = (Element)xmlResponse.getElementsByTagName("version").item(0);
        if (versionElement == null) {
            return 0;
        }
        return Integer.parseInt(versionElement.getFirstChild().getNodeValue());
    }


    /**
     * Extracts the AC from the VOMS response.
     * 
     * @return a string containing the AC.
     */
    public String getACAsString(){
        
        Element acElement = (Element) xmlResponse.getElementsByTagName( "ac" )
            .item( 0 );
        
        return acElement.getFirstChild().getNodeValue();
        
    }

    /**
     * 
     * Extracts the error messages from the VOMS response.
     * 
     * @return an array of {@link VOMSErrorMessage} objects.
     */
    public VOMSErrorMessage[] errorMessages() {

        NodeList nodes = xmlResponse.getElementsByTagName( "item" );

        if ( nodes.getLength() == 0 )
            return null;

        VOMSErrorMessage[] result = new VOMSErrorMessage[nodes.getLength()];

        for ( int i = 0; i < nodes.getLength(); i++ ) {

            Element itemElement = (Element) nodes.item( i );

            Element numberElement = (Element) itemElement.getElementsByTagName(
                    "number" ).item( 0 );
            Element messageElement = (Element) itemElement
                    .getElementsByTagName( "message" ).item( 0 );

            int number = Integer.parseInt( numberElement
                                 .getFirstChild().getNodeValue() );

            if (number >= ERROR_OFFSET) {
                result[i] = new VOMSErrorMessage( number, messageElement
                         .getFirstChild().getNodeValue() );
            }
        }
        
        return result;
    }

    public VOMSWarningMessage[] warningMessages() {

        NodeList nodes = xmlResponse.getElementsByTagName( "item" );

        if ( nodes.getLength() == 0 )
            return null;

        VOMSWarningMessage[] result = new VOMSWarningMessage[nodes.getLength()];

        for ( int i = 0; i < nodes.getLength(); i++ ) {

            Element itemElement = (Element) nodes.item( i );

            Element numberElement = (Element) itemElement.getElementsByTagName(
                    "number" ).item( 0 );
            Element messageElement = (Element) itemElement
                    .getElementsByTagName( "message" ).item( 0 );

            int number = Integer.parseInt( numberElement
                                 .getFirstChild().getNodeValue() );

            if (number < ERROR_OFFSET) {
                result[i] = new VOMSWarningMessage( number, messageElement
                         .getFirstChild().getNodeValue() );
            }
        }
        
        return result;
    }

    /**
     * Builds a VOMSResponse starting from a DOM an XML document (see {@link Document}).
     * 
     * @param res
     */
    public VOMSResponse(Document res){
        this.xmlResponse = res;
    }
}
