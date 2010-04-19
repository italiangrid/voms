/*********************************************************************
 *
 * Authors: Vincenzo Ciaschini - Vincenzo.Ciaschini@cnaf.infn.it 
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


package org.glite.voms;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.Vector;

/**
 * The job of this class is to represent a *.lsc file in the vomsdir
 * directory.
 *
 * @author Vincenzo Ciaschini.
 */
public class LSCFile {
    private String name = null;
    private Vector dnGroups = null;

    /**
     * Loads a *.lsc file from a File
     *
     * @param f the file to load from
     *
     * @throws IOException if there are problems loading the file.
     */
    public LSCFile(File f) throws IOException {
        parse(f);
    }

    /**
     * Returns the basename of the file from which this was loaded.
     *
     * @return the filename, or null if nothing was loaded.
     */
    public String getName() {
        return name;
    }

    private LSCFile parse(File theFile) throws IOException {
        BufferedReader theBuffer = null;
        try {
            dnGroups = new Vector();

            name = PKIUtils.getBaseName(theFile);
            
            theBuffer = new BufferedReader(new FileReader(theFile));

            String s = null;

            s = theBuffer.readLine();

            Vector dnList = new Vector();

            while (s != null) {
                s = s.trim();
                if (!(s.length() == 0 || s.startsWith("#"))) {
                    if (!s.startsWith("-")) {
                        dnList.add(s);
                    }
                    else {
                        dnGroups.add(dnList);
                        dnList = new Vector();
                    }
                }

                s = theBuffer.readLine();
            }

            dnGroups.add(dnList);
        }
        finally {
            if (theBuffer != null)
                theBuffer.close();
        }
        return this;
    }

    /**
     * Returns the allowed subject/issuer DN sequences for this file.
     *
     * @return a vector whose elements are vectors of strings describing
     * the exact sequences.
     */
    public Vector getDNLists() {
        return dnGroups;
    }
}
