/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2012 The ZAP Development Team
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
package org.zaproxy.zap.extension.pscanrules;

import java.util.List;
import java.util.Locale;
import java.util.Map;
import net.htmlparser.jericho.Source;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

public class XContentTypeOptionsScanRule extends PluginPassiveScanner {

    /** Prefix for internationalized messages used by this rule */
    private static final String MESSAGE_PREFIX = "pscanrules.xcontenttypeoptions.";

    private static final int PLUGIN_ID = 10021;

    private static final Map<String, String> ALERT_TAGS =
            CommonAlertTag.toMap(
                    CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG,
                    CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG);

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        boolean includeErrorRedirectResponses = false;
        switch (this.getAlertThreshold()) {
            case LOW:
                includeErrorRedirectResponses = true;
                break;
            case HIGH:
            case MEDIUM:
            default:
        }
        if (msg.getResponseBody().length() > 0) {
            int responseStatus = msg.getResponseHeader().getStatusCode();
            // If it's an error and we're not including error responses then just return without
            // alerting
            if (!includeErrorRedirectResponses
                    && (getHelper().isServerError(msg)
                            || getHelper().isClientError(msg)
                            || HttpStatusCode.isRedirection(responseStatus))) {
                return;
            }
            List<String> xContentTypeOptions =
                    msg.getResponseHeader().getHeaderValues(HttpHeader.X_CONTENT_TYPE_OPTIONS);
            if (xContentTypeOptions.isEmpty()) {
                this.raiseAlert(msg, id, "");
            } else {
                for (String xContentTypeOptionsDirective : xContentTypeOptions) {
                    // 'nosniff' is currently the only defined value for this header, so this logic
                    // is ok
                    if (xContentTypeOptionsDirective.toLowerCase(Locale.ROOT).indexOf("nosniff")
                            < 0) {
                        this.raiseAlert(msg, id, xContentTypeOptionsDirective);
                    }
                }
            }
        }
    }

    private void raiseAlert(HttpMessage msg, int id, String xContentTypeOption) {
        newAlert()
                .setRisk(getRisk())
                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                .setDescription(getDescription())
                .setParam(HttpHeader.X_CONTENT_TYPE_OPTIONS)
                .setOtherInfo(getOtherInfo())
                .setSolution(getSolution())
                .setReference(getReference())
                .setEvidence(xContentTypeOption)
                .setCweId(getCweId())
                .setWascId(getWascId())
                .raise();
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    @Override
    public int getPluginId() {
        return PLUGIN_ID;
    }

    public int getRisk() {
        return Alert.RISK_LOW;
    }

    public String getDescription() {
        return Constant.messages.getString(MESSAGE_PREFIX + "desc");
    }

    public String getOtherInfo() {
        return Constant.messages.getString(MESSAGE_PREFIX + "otherinfo");
    }

    public String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    public String getReference() {
        return Constant.messages.getString(MESSAGE_PREFIX + "refs");
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    public int getCweId() {
        return 693; // CWE-693: Protection Mechanism Failure
    }

    public int getWascId() {
        return 15; // WASC-15: Application Misconfiguration
    }
}
