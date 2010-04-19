/*********************************************************************
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
/*
 * Copyright (c) Members of the EGEE Collaboration. 2004.
 * See http://eu-egee.org/partners/ for details on the copyright holders.
 * For license conditions see the license file or http://eu-egee.org/license.html
 */

package org.glite.voms;


/**
 * Parses and assembles Fully Qualified Attribute Names
 * (FQANs) used by VOMS.
 *
 * FQANs are defined as<br>
 * <code>&lt;group&gt;[/Role=[&lt;role&gt;][/Capability=&lt;capability&gt;]]</code>
 *
 * @author mulmo
 */
public class FQAN {
    String fqan;
    String group;
    String role;
    String capability;
    boolean split = false;

    public FQAN(String fqan) {
        this.fqan = fqan;
    }

    public FQAN(String group, String role, String capability) {
        this.group = group;
        this.role = role;
        this.capability = capability;
        this.split = true;
    }

    public String getFQAN() {
        if (fqan != null) {
            return fqan;
        }

        fqan = group + "/Role=" + ((role != null) ? role : "") +
            ((capability != null) ? ("/Capability=" + capability) : "");

        return fqan;
    }

    protected void split() {
        if (split) {
            return;
        }

        split = true;

        if (fqan == null) {
            return;
        }

        int i = fqan.indexOf("/Role=");

        if (i < 0) {
            group = fqan;

            return;
        }

        group = fqan.substring(0, i);

        int j = fqan.indexOf("/Capability=", i + 6);
        String s = (j < 0) ? fqan.substring(i + 6) : fqan.substring(i + 6, j);
        role = (s.length() == 0) ? null : s;
        s = (j < 0) ? null : fqan.substring(j + 12);
        capability = ((s == null) || (s.length() == 0)) ? null : s;
    }

    public String getGroup() {
        if (!split) {
            split();
        }

        return group;
    }

    public String getRole() {
        if (!split) {
            split();
        }

        return role;
    }

    public String getCapability() {
        if (!split) {
            split();
        }

        return capability;
    }

    public boolean equals(Object o) {
        if (o == null) {
            return false;
        }

        if (o instanceof FQAN || o instanceof String) {
            return toString().equals(o.toString());
        }

        return false;
    }

    public int hashCode() {
        return toString().hashCode();
    }

    public String toString() {
        return getFQAN();
    }
}
