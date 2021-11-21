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

import java.util.Map;
import net.htmlparser.jericho.Source;
import org.apache.commons.lang.StringUtils;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/** @author albertov91 */
public class WSDLFilePassiveScanRule extends PluginPassiveScanner {

    /** Prefix for internationalized messages used by this rule */
    private static final String MESSAGE_PREFIX = "soap.wsdlfilepscan.";

    private static final Map<String, String> ALERT_TAGS =
            CommonAlertTag.toMap(
                    CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG,
                    CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG);

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        if (getHelper().isPage404(msg) || getHelper().isPage500(msg)) {
            return;
        }
        if (isWsdl(msg)) {
            HttpResponseHeader header = msg.getResponseHeader();
            String contentType = header.getHeader(HttpHeader.CONTENT_TYPE).trim();
            raiseAlert(contentType);
        }
    }

    public boolean isWsdl(HttpMessage msg) {
        if (msg == null) {
            return false;
        }
        if (msg.getResponseBody().length() > 0
                && msg.getResponseHeader().isText()
                && !msg.getResponseHeader().isHtml()) {
            /* Alerts that a public WSDL file has been found. */
            HttpResponseHeader header = msg.getResponseHeader();
            String baseURL = msg.getRequestHeader().getURI().toString().trim();
            String contentType = header.getHeader(HttpHeader.CONTENT_TYPE).trim();
            return baseURL.endsWith(".wsdl")
                    || StringUtils.endsWithIgnoreCase(baseURL, "?wsdl")
                    || contentType.equals("application/wsdl+xml");
        }
        return false;
    }

    private void raiseAlert(String evidence) {
        newAlert()
                .setRisk(Alert.RISK_INFO)
                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                .setDescription(getDescription())
                .setOtherInfo(getOtherInfo())
                .setSolution(getSolution())
                .setReference(getReference())
                .setEvidence(evidence)
                .setWascId(13)
                .raise();
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

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }
}
