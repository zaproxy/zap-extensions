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
import net.htmlparser.jericho.Source;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

public class ContentTypeMissingScanRule extends PluginPassiveScanner {

    /** Prefix for internationalised messages used by this rule */
    private static final String MESSAGE_PREFIX = "pscanrules.contenttypemissing.";

    private static final int PLUGIN_ID = 10019;

    @Override
    public void scanHttpRequestSend(HttpMessage msg, int id) {
        // ignore
    }

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
                .setRisk(Alert.RISK_INFO)
                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                .setDescription(getDescription())
                .setParam(contentType)
                .setSolution(getSolution())
                .setReference(getReference())
                .setCweId(345) // CWE Id 345 - Insufficient Verification of Data Authenticity
                .setWascId(12) // WASC Id 12 - Content Spoofing
                .raise();
    }

    @Override
    public void setParent(PassiveScanThread parent) {
        // Nothing to do.
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    private String getDescription() {
        return Constant.messages.getString(MESSAGE_PREFIX + "desc");
    }

    private String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    private String getReference() {
        return Constant.messages.getString(MESSAGE_PREFIX + "refs");
    }

    @Override
    public int getPluginId() {
        return PLUGIN_ID;
    }
}
