/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
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
package org.zaproxy.zap.extension.soap;

import com.predic8.wsdl.BindingOperation;
import com.predic8.wsdl.Definitions;
import com.predic8.wsdl.Port;
import java.util.HashMap;

/**
 * This class encapsulates all required variables to craft a SOAP request message.
 *
 * @author Albertov91
 */
public class SOAPMsgConfig {

    private Definitions wsdl;
    private int soapVersion = 0;
    private HashMap<String, String> params;
    private Port port;
    private BindingOperation bindOp;

    /* Constructors. */
    public SOAPMsgConfig() {}

    public SOAPMsgConfig(
            Definitions wsdl,
            int soapVersion,
            HashMap<String, String> params,
            Port port,
            BindingOperation bindOp) {
        this.setWsdl(wsdl);
        this.setSoapVersion(soapVersion);
        this.setParams(params);
        this.setPort(port);
        this.setBindOp(bindOp);
    }

    /* Custom methods. */
    public boolean isComplete() {
        return this.wsdl != null
                && this.soapVersion >= 1
                && this.soapVersion <= 2
                && this.params != null
                && this.port != null
                && this.bindOp != null;
    }

    /* Getters and Setters. */
    public Definitions getWsdl() {
        return wsdl;
    }

    public void setWsdl(Definitions wsdl) {
        this.wsdl = wsdl;
    }

    public int getSoapVersion() {
        return soapVersion;
    }

    public void setSoapVersion(int soapVersion) {
        this.soapVersion = soapVersion;
    }

    public HashMap<String, String> getParams() {
        return params;
    }

    public void setParams(HashMap<String, String> params) {
        this.params = params;
    }

    public Port getPort() {
        return port;
    }

    public void setPort(Port port) {
        this.port = port;
    }

    public BindingOperation getBindOp() {
        return bindOp;
    }

    public void setBindOp(BindingOperation bindOp) {
        this.bindOp = bindOp;
    }

    public boolean equals(SOAPMsgConfig other) {
        return this.getHash() == other.getHash();
    }

    private int getHash() {
        StringBuilder sb = new StringBuilder();
        sb.append("InitialContent"); // Just in case all parameters are null.
        if (this.wsdl != null) sb.append(this.wsdl.getAsString());
        sb.append(this.soapVersion);
        if (params != null) {
            for (String value : params.values()) {
                sb.append(value);
            }
        }
        if (port != null && port.getAddress() != null)
            sb.append(this.port.getAddress().getLocation());
        if (bindOp != null) sb.append(bindOp.getName());
        return sb.toString().hashCode();
    }
}
