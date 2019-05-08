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

import java.util.LinkedHashSet;
import java.util.Set;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElementWrapper;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement(namespace = "org.zaproxy.zap.extension.saml")
public class SAMLConfigData {
    private boolean autoChangerEnabled;
    private boolean xswEnabled;
    private boolean validationEnabled;
    private boolean deflateOnSendEnabled = true;

    private Set<Attribute> availableAttributes;

    private Set<Attribute> autoChangeValues;

    /**
     * Get whether the autochanger is enabled
     *
     * @return
     */
    public boolean isAutoChangerEnabled() {
        return autoChangerEnabled;
    }

    /**
     * Set auto changer enabled/disabled
     *
     * @param autoChangerEnabled
     */
    public void setAutoChangerEnabled(boolean autoChangerEnabled) {
        this.autoChangerEnabled = autoChangerEnabled;
    }

    /**
     * Get whether the deflateOnSend is enabled
     *
     * @return
     */
    public boolean isDeflateOnSendEnabled() {
        return deflateOnSendEnabled;
    }

    /**
     * Set deflateOnSend enabled/disabled
     *
     * @param deflateOnSendEnabled
     */
    public void setDeflateOnSendEnabled(boolean deflateOnSendEnabled) {
        this.deflateOnSendEnabled = deflateOnSendEnabled;
    }

    /**
     * Get the set of all available attributes
     *
     * @return
     */
    @XmlElementWrapper(name = "AllAttributes")
    @XmlElement(name = "Attribute")
    public Set<Attribute> getAvailableAttributes() {
        if (availableAttributes == null) {
            availableAttributes = new LinkedHashSet<>();
        }
        return availableAttributes;
    }

    /**
     * Setter for get available attributes
     *
     * @param availableAttributes
     */
    public void setAvailableAttributes(Set<Attribute> availableAttributes) {
        this.availableAttributes = availableAttributes;
    }

    /**
     * Get the auto change attributes to be used by passive scanner
     *
     * @return
     */
    public Set<Attribute> getAutoChangeValues() {
        if (autoChangeValues == null) {
            autoChangeValues = new LinkedHashSet<>();
        }
        return autoChangeValues;
    }

    /**
     * Set the auto change attributes
     *
     * @param autoChangeValues
     */
    @XmlElementWrapper(name = "AutoChangeAttributes")
    @XmlElement(name = "Attribute")
    public void setAutoChangeValues(Set<Attribute> autoChangeValues) {
        this.autoChangeValues = autoChangeValues;
    }

    /**
     * Get whether the Signature removal is enabled
     *
     * @return
     */
    public boolean isXswEnabled() {
        return xswEnabled;
    }

    /**
     * Enable/Disable signature removal
     *
     * @param xswEnabled
     */
    public void setXswEnabled(boolean xswEnabled) {
        this.xswEnabled = xswEnabled;
    }

    /**
     * Get whether the data type validation is enabled. If enabled the values of attributes should
     * have the values matching to the type
     *
     * @return
     */
    public boolean isValidationEnabled() {
        return validationEnabled;
    }

    /**
     * Enable/ Disable the attribute type validation
     *
     * @param validationEnabled
     */
    public void setValidationEnabled(boolean validationEnabled) {
        this.validationEnabled = validationEnabled;
    }
}
