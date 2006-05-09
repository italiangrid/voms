package org.glite.security.voms;

import org.glite.security.voms.peers.*;

public class Attribute {
    private AttributePeer attribute = null;

    Attribute(AttributePeer attr) {
        attribute = attr;
    }

    public String getName() {
        return attribute.name;
    }

    public String getValue() {
        return attribute.value;
    }

    public String getQualifier() {
        return attribute.qualifier;
    }
}
