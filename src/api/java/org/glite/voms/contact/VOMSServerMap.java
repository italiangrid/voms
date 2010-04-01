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

import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.Map.Entry;

import org.apache.commons.lang.StringUtils;


/**
 * 
 * A {@link VOMSServerMap} organizes voms servers found in vomses configuration files
 * in map keyed by vo. This way is easy to know which servers acts as replicas for the 
 * same vos. For more info about vomses configuration files, see {@link VOMSESFileParser}.
 * 
 * @author Andrea Ceccanti
 * @author Vincenzo Ciaschini
 *
 */
public class VOMSServerMap {

    protected Map map = new TreeMap();
    
    public void add(VOMSServerInfo info){
        String key = info.getAlias();
        
        if (map.containsKey( key )){
            
            Set servers = (Set) map.get( key );
            servers.add( info );
            return;
        }
        
        Set l = new HashSet();
        l.add( info );
        map.put( key, l);
    }
    
    public Set get(String nick){
        
        return (Set) map.get( nick );
        
    }
        
    public int serverCount(String nick){
        
        if (map.containsKey( nick ))
            return ((Set)map.get( nick )).size();
        
        return 0;
    }
    
    /**
     * Merge this map with another {@link VOMSServerMap} object.
     * @param other
     */
    public void merge(VOMSServerMap other){
        
        Iterator i = other.map.entrySet().iterator();
        
        while (i.hasNext()){
            Map.Entry e = (Entry) i.next();
         
            if (map.containsKey( e.getKey() ))
                get((String)e.getKey()).addAll( (Set )e.getValue());
            else
                map.put( e.getKey(), e.getValue());
        }
    }
    
    public String toString() {
        
        if (map == null || map.isEmpty())
            return "[]";
        
        StringBuilder buf = new StringBuilder();
        
        Iterator i = map.entrySet().iterator();
        buf.append( "VOMSServerMap:[\n");
        
        while (i.hasNext()){
            Map.Entry e = (Entry) i.next();
            
            buf.append(e.getKey()+":\n");
            buf.append( "\tnum_servers: "+((Set)e.getValue()).size()+"\n" );
            buf.append( "\tserver_details: \n\t\t"+ StringUtils.join(((Set)e.getValue()).iterator(),"\n\t\t") +"\n" );
        }
        buf.append("]\n");
        
        return buf.toString(); 
        
    }
}
