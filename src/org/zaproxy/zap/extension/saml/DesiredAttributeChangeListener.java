package org.zaproxy.zap.extension.saml;

import java.util.Set;

public interface DesiredAttributeChangeListener {
    void onDesiredAttributeValueChange(Attribute attribute);
    void onAddDesiredAttribute(Attribute attribute);
    void onDeleteDesiredAttribute(Attribute attribute);
    Set<Attribute> getDesiredAttributes();
}
