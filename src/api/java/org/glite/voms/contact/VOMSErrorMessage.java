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


/**
 * 
 * This class is used to decode VOMS error messages contained in a VOMS 
 * response.
 * 
 * @author Andrea Ceccanti
 * @author Vincenzo Ciaschini
 *
 */
public class VOMSErrorMessage extends VOMSMessage {
    
    public VOMSErrorMessage(int code, String message){
        super(code, message);
    }
    
    public String toString() {
        
        return "voms error "+code+": "+message;        
        
    }
}
