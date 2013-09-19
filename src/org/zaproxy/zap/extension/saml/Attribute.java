package org.zaproxy.zap.extension.saml;

import javax.xml.bind.annotation.XmlEnum;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
public class Attribute {

    @XmlEnum
    public static enum SAMLAttributeValueType {
        String,
        Integer,
        Decimal,
        TimeStamp
    }

    private String name;
    private String xPath;
    private String viewName;
    private SAMLAttributeValueType valueType;
    private Object value;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getxPath() {
        return xPath;
    }

    public void setxPath(String xPath) {
        this.xPath = xPath;
    }

    public String getViewName() {
        return viewName;
    }

    public void setViewName(String viewName) {
        this.viewName = viewName;
    }

    public SAMLAttributeValueType getValueType() {
        return valueType;
    }

    public void setValueType(SAMLAttributeValueType valueType) {
        this.valueType = valueType;
    }

    public Object getValue() {
        return value;
    }

    public void setValue(Object value) {
        this.value = value;
    }

    public Attribute createCopy(){
        Attribute attribute = new Attribute();
        attribute.setxPath(xPath);
        attribute.setName(name);
        attribute.setViewName(viewName);
        attribute.setValueType(valueType);
        return attribute;
    }

    @Override
    public String toString() {
        return viewName;
    }
}
