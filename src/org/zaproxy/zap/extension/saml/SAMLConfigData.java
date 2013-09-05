package org.zaproxy.zap.extension.saml;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElementWrapper;
import javax.xml.bind.annotation.XmlRootElement;
import java.util.LinkedHashSet;
import java.util.Set;

@XmlRootElement(namespace = "org.zaproxy.zap.extension.saml")
public class SAMLConfigData {
    private boolean autoChangerEnabled;
    private boolean xswEnabled;

   private Set<Attribute> availableAttributes;

    private Set<Attribute> autoChangeValues;

    public boolean isAutoChangerEnabled() {
        return autoChangerEnabled;
    }

    public void setAutoChangerEnabled(boolean autoChangerEnabled) {
        this.autoChangerEnabled = autoChangerEnabled;
    }

    @XmlElementWrapper(name = "AllAttributes")
    @XmlElement(name = "Attribute")
    public Set<Attribute> getAvailableAttributes() {
        if(availableAttributes==null){
            availableAttributes = new LinkedHashSet<>();
        }
        return availableAttributes;
    }

    public void setAvailableAttributes(Set<Attribute> availableAttributes) {
        this.availableAttributes = availableAttributes;
    }

    public Set<Attribute> getAutoChangeValues() {
        if(autoChangeValues==null){
            autoChangeValues = new LinkedHashSet<>();
        }
        return autoChangeValues;
    }

    @XmlElementWrapper(name = "AutoChangeAttributes")
    @XmlElement(name = "Attribute")
    public void setAutoChangeValues(Set<Attribute> autoChangeValues) {
        this.autoChangeValues = autoChangeValues;
    }

    public boolean isXswEnabled() {
        return xswEnabled;
    }

    public void setXswEnabled(boolean xswEnabled) {
        this.xswEnabled = xswEnabled;
    }
}
