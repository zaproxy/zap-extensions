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
import java.util.Map;
import net.htmlparser.jericho.Source;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

public class ContentTypeMissingScanRule extends PluginPassiveScanner {

    /** Prefix for internationalised messages used by this rule */
    private static final String MESSAGE_PREFIX = "pscanrules.contenttypemissing.";

    private static final Map<String, String> ALERT_TAGS =
            CommonAlertTag.toMap(
                    CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG,
                    CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG);

    private static final int PLUGIN_ID = 10019;

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        if (msg.getResponseBody().length() > 0) {
            List<String> contentType =
                    msg.getResponseHeader().getHeaderValues(HttpHeader.CONTENT_TYPE);
            if (!contentType.isEmpty()) {
                for (String contentTypeDirective : contentType) {
                    if (contentTypeDirective.isEmpty()) {
                        this.raiseAlert(msg, id, contentTypeDirective, false);
                    }
                }
            } else {
                this.raiseAlert(msg, id, "", true);
            }
        }
    }

    private void raiseAlert(
            HttpMessage msg, int id, String contentType, boolean isContentTypeMissing) {
        String issue = Constant.messages.getString(MESSAGE_PREFIX + "name.empty");
        if (isContentTypeMissing) {
            issue = getName();
        }

        newAlert()
                .setName(issue)
                .setRisk(getRisk())
                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                .setDescription(getDescription())
                .setParam(contentType)
                .setSolution(getSolution())
                .setReference(getReference())
                .setCweId(getCweId())
                .setWascId(getWascId())
                .raise();
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    public String getDescription() {
        return Constant.messages.getString(MESSAGE_PREFIX + "desc");
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
        return 345; // CWE Id 345 - Insufficient Verification of Data Authenticity
    }

    public int getWascId() {
        return 12; // WASC Id 12 - Content Spoofing
    }

    public int getRisk() {
        return Alert.RISK_INFO;
    }

    @Override
    public int getPluginId() {
        return PLUGIN_ID;
    }
}
