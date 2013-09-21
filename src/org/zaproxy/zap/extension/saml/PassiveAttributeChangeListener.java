package org.zaproxy.zap.extension.saml;

import java.util.Set;

public interface PassiveAttributeChangeListener {

    /**
     * Called on new auto change attribute's value change
     *
     * @param attribute
     */
    void onDesiredAttributeValueChange(Attribute attribute);

    /**
     * Called on new auto change attribute add event
     *
     * @param attribute
     */
    void onAddDesiredAttribute(Attribute attribute);

    /**
     * Called on new auto change attribute's remove event
     *
     * @param attribute
     */
    void onDeleteDesiredAttribute(Attribute attribute);

    /**
     * Get the current auto change attributes
     *
     * @param attribute
     */
    Set<Attribute> getDesiredAttributes();
}
