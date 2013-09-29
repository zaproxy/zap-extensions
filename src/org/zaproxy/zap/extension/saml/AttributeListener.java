package org.zaproxy.zap.extension.saml;

public interface AttributeListener {
    /**
     * Called on new attribute add event
     * @param a
     */
    void onAttributeAdd(Attribute a);

    /**
     * Called on delete event of attribute
     * @param a
     */
    void onAttributeDelete(Attribute a);
}
