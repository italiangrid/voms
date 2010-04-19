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


/**
 * 
 * This class is used to decode VOMS error messages contained in a VOMS 
 * response.
 * 
 * @author Andrea CEccanti
 *
 */
public class VOMSMessage {
    
    int code;
    String message;
    
    public int getCode() {
    
        return code;
    }
    
    public void setCode( int code ) {
    
        this.code = code;
    }
    
    public String getMessage() {
    
        return message;
    }
    
    public void setMessage( String message ) {
    
        this.message = message;
    }
    
    public VOMSMessage(int code, String message){
        
        this.code = code;
        this.message = message;
    }
    
    public String toString() {
        return "voms message "+code+": "+message;        
    }
}
