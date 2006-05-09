package org.glite.security.voms;

import org.glite.security.voms.peers.*;

public class AttributeList {
    private AttributeListPeer attribList = null;

    AttributeList(AttributeListPeer attribs) {
        attribList = attribs;
    }

    public int getSize() {
        return attribList.attributes.length;
    }

    public String getGrantor() {
        return attribList.grantor;
    }

    public Attribute getElement(int i) {
        if (i < attribList.attributes.length) {
            return new Attribute(attribList.attributes[i]);
        }
        else {
            throw new IllegalArgumentException("Index out of bounds");
        }
    }
}
