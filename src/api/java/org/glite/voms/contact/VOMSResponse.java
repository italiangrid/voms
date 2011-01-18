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

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.apache.log4j.Logger;

/**
 * 
 * This class is used to parse and represent VOMS server responses.
 *  
 * @author Andrea Ceccanti
 * @author Vincenzo Ciaschini
 *
 */
public class VOMSResponse {

    private static int ERROR_OFFSET = 1000;
    private static final Logger log = Logger.getLogger( VOMSResponse.class );

    protected Document xmlResponse;

    public boolean hasErrors() {
        // handle REST case first
        if (xmlResponse.getElementsByTagName("error").getLength() != 0)
            return true;

        // errors imply that no AC were created
        return ((xmlResponse.getElementsByTagName( "item" ).getLength() != 0) &&
                (xmlResponse.getElementsByTagName( "ac" ).getLength() == 0));
    }

    public boolean hasWarnings() {
        // handle REST case first
        if (xmlResponse.getElementsByTagName("warning").getLength() != 0)
            return true;

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
        
        if (acElement != null)
            return VOMSDecoder.decode( acElement.getFirstChild().getNodeValue()); 
        else
            return null;
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

        VOMSErrorMessage[] result = errorMessagesREST();
        if (result != null)
            return result;

        NodeList nodes = xmlResponse.getElementsByTagName( "item" );

        if ( nodes.getLength() == 0 )
            return null;

        result = new VOMSErrorMessage[nodes.getLength()];

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

    private VOMSErrorMessage[] errorMessagesREST() {
        NodeList nodes = xmlResponse.getElementsByTagName( "error");

        if (nodes.getLength() == 0)
            return null;

        VOMSErrorMessage[] result = new VOMSErrorMessage[nodes.getLength()];

        for (int i = 0; i < nodes.getLength(); i++) {
            Element itemElement = (Element) nodes.item(i);

            Element codeElement = (Element)itemElement.getElementsByTagName("code").item(0);
            Element messageElement = (Element)itemElement.getElementsByTagName("message").item(0);
            String strcode = codeElement.getFirstChild().getNodeValue();
            int code;

            if (strcode.equals("NoSuchUser"))
                code = 1001;
            else if (strcode.equals("BadRequest"))
                code = 1005;
            else if (strcode.equals("SuspendedUser"))
                code = 1004;
            else // InternalError
                code = 1006;

            result[i] = new VOMSErrorMessage(code, messageElement.getFirstChild().getNodeValue());
        }
        return result;
    }

    public VOMSWarningMessage[] warningMessages() {
        VOMSWarningMessage[] result = warningMessagesREST();
        if (result != null)
            return result;

        NodeList nodes = xmlResponse.getElementsByTagName( "item" );

        if ( nodes.getLength() == 0 )
            return null;

        result = new VOMSWarningMessage[nodes.getLength()];

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

    private VOMSWarningMessage[] warningMessagesREST() {
        NodeList nodes = xmlResponse.getElementsByTagName( "warning" );

        if ( nodes.getLength() == 0 )
            return null;

        VOMSWarningMessage[] result = new VOMSWarningMessage[nodes.getLength()];

        for ( int i = 0; i < nodes.getLength(); i++ ) {

            Element itemElement = (Element) nodes.item( i );

            Element messageElement = (Element) itemElement
                    .getElementsByTagName( "message" ).item( 0 );

            String message = itemElement.getFirstChild().getNodeValue();
            int number;

            if (message.contains("validity"))
                number = 2;
            else if (message.contains("selected"))
                number = 1;
            else if (message.contains("contains attributes"))
                number = 3;
            else
                number = 4;

            log.debug("Message = " + message + " number = " + number);
            if (number < ERROR_OFFSET) {
                result[i] = new VOMSWarningMessage( number, message);
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
