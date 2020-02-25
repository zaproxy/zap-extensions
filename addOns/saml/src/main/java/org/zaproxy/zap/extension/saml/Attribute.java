/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2013 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.saml;

import javax.xml.bind.annotation.XmlEnum;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
public class Attribute {

    /**
     * The Enum for the Attribute value type. It can be one of String, Integer,Decimal(Floating
     * point) or TimeStamp
     */
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

    /**
     * Get the attribute's unique name
     *
     * @return
     */
    public String getName() {
        return name;
    }

    /**
     * Set the attribute name
     *
     * @param name
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * Get Xpath of the attribute. In the saml messages this xpath will be evaluated and the value
     * of that will be taken as the attribute value
     *
     * @return
     */
    public String getxPath() {
        return xPath;
    }

    /**
     * Set Xpath of attribute
     *
     * @see #getxPath()
     * @param xPath
     */
    public void setxPath(String xPath) {
        this.xPath = xPath;
    }

    /**
     * Get the human friendly name of the attribute. This may be different from the name, if the
     * name is too long or contain special characters.
     *
     * @return
     */
    public String getViewName() {
        return viewName;
    }

    /**
     * Set the human readable attribute view name
     *
     * @see #getViewName()
     * @param viewName
     */
    public void setViewName(String viewName) {
        this.viewName = viewName;
    }

    /**
     * Get the data type of the attribute.
     *
     * @see SAMLAttributeValueType
     * @return
     */
    public SAMLAttributeValueType getValueType() {
        return valueType;
    }

    /**
     * Set the data type of the attribute.
     *
     * @see #getValueType()
     * @param valueType
     */
    public void setValueType(SAMLAttributeValueType valueType) {
        this.valueType = valueType;
    }

    /**
     * Get the value of the attribute if set
     *
     * @return
     */
    public Object getValue() {
        return value;
    }

    /**
     * Set the value of the given attribute to the given value
     *
     * @param value
     */
    public void setValue(Object value) {
        this.value = value;
    }

    /**
     * Create a copy of attribute. The new attribute object will have the exact values for the
     * fields except for the value field which is null
     *
     * @return
     */
    public Attribute createCopy() {
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

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        Attribute attribute = (Attribute) o;
        return name.equals(attribute.name);
    }

    @Override
    public int hashCode() {
        return name.hashCode();
    }
}
