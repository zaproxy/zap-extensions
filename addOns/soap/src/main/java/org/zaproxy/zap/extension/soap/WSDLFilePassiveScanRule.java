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

import net.htmlparser.jericho.Source;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/** @author albertov91 */
public class WSDLFilePassiveScanRule extends PluginPassiveScanner {

    /** Prefix for internationalized messages used by this rule */
    private static final String MESSAGE_PREFIX = "soap.wsdlfilepscan.";

    private PassiveScanThread parent = null;

    @Override
    public void scanHttpRequestSend(HttpMessage msg, int id) {
        // Only checking the response.
    }

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        if (isWsdl(msg)) {
            HttpResponseHeader header = msg.getResponseHeader();
            String contentType = header.getHeader(HttpHeader.CONTENT_TYPE).trim();
            raiseAlert(msg, id, contentType);
        }
    }

    public boolean isWsdl(HttpMessage msg) {
        if (msg == null) return false;
        if (msg.getResponseBody().length() > 0 && msg.getResponseHeader().isText()) {
            /* Alerts that a public WSDL file has been found. */
            HttpResponseHeader header = msg.getResponseHeader();
            String baseURL = msg.getRequestHeader().getURI().toString().trim();
            String contentType = header.getHeader(HttpHeader.CONTENT_TYPE).trim();
            if (baseURL.endsWith(".wsdl")
                    || contentType.equals("text/xml")
                    || contentType.equals("application/wsdl+xml")) {
                return true;
            }
        }
        return false;
    }

    private void raiseAlert(HttpMessage msg, int id, String evidence) {
        Alert alert = new Alert(getPluginId(), Alert.RISK_INFO, Alert.CONFIDENCE_MEDIUM, getName());
        alert.setDetail(
                this.getDescription(),
                msg.getRequestHeader().getURI().toString(),
                "", // Param, not relevant
                // for this example
                // vulnerability
                "", // Attack, not relevant for passive vulnerabilities
                this.getOtherInfo(),
                this.getSolution(),
                this.getReference(),
                evidence, // Evidence
                0, // CWE Id - return 0 if no relevant one
                13, // WASC Id - Info leakage (return 0 if no relevant one)
                msg);

        parent.raiseAlert(id, alert);
    }

    @Override
    public void setParent(PassiveScanThread parent) {
        this.parent = parent;
    }

    @Override
    public int getPluginId() {
        return 90030;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    private String getDescription() {
        return Constant.messages.getString(MESSAGE_PREFIX + "desc");
    }

    private String getOtherInfo() {
        return Constant.messages.getString(MESSAGE_PREFIX + "other");
    }

    private String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    private String getReference() {
        return Constant.messages.getString(MESSAGE_PREFIX + "refs");
    }
}
