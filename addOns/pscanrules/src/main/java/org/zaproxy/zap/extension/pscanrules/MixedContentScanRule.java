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

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.HTMLElementName;
import net.htmlparser.jericho.Source;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

public class MixedContentScanRule extends PluginPassiveScanner
        implements CommonPassiveScanRuleInfo {

    /** Prefix for internationalised messages used by this rule */
    private static final String MESSAGE_PREFIX = "pscanrules.mixedcontent.";

    private static final Map<String, String> ALERT_TAGS =
            CommonAlertTag.toMap(
                    CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG,
                    CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG,
                    CommonAlertTag.WSTG_V42_CRYP_03_CRYPTO_FAIL);

    private static final int PLUGIN_ID = 10040;

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        if (!msg.getRequestHeader().isSecure()) {
            // If SSL/TLS isn't used then this check isn't relevant
            return;
        }

        if (msg.getResponseBody().length() == 0 || !msg.getResponseHeader().isHtml()) {
            // No point attempting to parse non-HTML content, it will not be correctly interpreted.
            return;
        }

        List<MixedContent> list = new ArrayList<>();
        boolean incScript = false;
        List<Element> sourceElements = source.getAllElements();
        for (Element sourceElement : sourceElements) {
            if (addAttsContainingHttpContent(sourceElement, "src", list)) {
                if (HTMLElementName.SCRIPT.equals(sourceElement.getName())) {
                    // Considered to be more serious
                    incScript = true;
                }
            }
            addAttsContainingHttpContent(sourceElement, "background", list);
            addAttsContainingHttpContent(sourceElement, "classid", list);
            addAttsContainingHttpContent(sourceElement, "codebase", list);
            addAttsContainingHttpContent(sourceElement, "data", list);
            addAttsContainingHttpContent(sourceElement, "icon", list);
            addAttsContainingHttpContent(sourceElement, "usemap", list);

            switch (this.getAlertThreshold()) {
                case LOW:
                case MEDIUM:
                    // These are a bit more debatable, so dont do them on the HIGH setting
                    addAttsContainingHttpContent(sourceElement, "action", list);
                    addAttsContainingHttpContent(sourceElement, "formaction", list);
                    break;
                default:
                    // No other checks
            }
        }

        final int numberOfMixedElements = list.size();
        if (numberOfMixedElements > 0) {
            StringBuilder sb = new StringBuilder(numberOfMixedElements * 40);
            for (MixedContent mc : list) {
                sb.append("tag=");
                sb.append(mc.getTag());
                sb.append(' ');
                sb.append(mc.getAtt());
                sb.append('=');
                sb.append(mc.getValue());
                sb.append('\n');
            }

            buildAlert(list.get(0).getValue(), sb.toString(), incScript).raise();
        }
    }

    private boolean addAttsContainingHttpContent(
            Element sourceElement, String attribute, List<MixedContent> list) {
        String val = sourceElement.getAttributeValue(attribute);
        if (val != null && val.toLowerCase().startsWith("http:")) {
            list.add(new MixedContent(sourceElement.getName(), attribute, val));
            return true;
        }
        return false;
    }

    private AlertBuilder buildAlert(String first, String all, boolean incScript) {
        String name = getName();
        int risk = Alert.RISK_LOW;
        if (incScript) {
            name = Constant.messages.getString(MESSAGE_PREFIX + "name.inclscripts");
            risk = Alert.RISK_MEDIUM;
        }
        return newAlert()
                .setName(name)
                .setRisk(risk)
                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                .setDescription(getDescription())
                .setOtherInfo(all)
                .setSolution(getSolution())
                .setReference(getReference())
                .setEvidence(first)
                .setCweId(getCweId())
                .setWascId(getWascId());
    }

    @Override
    public int getPluginId() {
        return PLUGIN_ID;
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
        return 311; // CWE Id 311 - Missing Encryption of Sensitive Data
    }

    public int getWascId() {
        return 4; // WASC Id 4 - Insufficient Transport Layer Protection
    }

    @Override
    public List<Alert> getExampleAlerts() {
        return List.of(
                buildAlert(
                                "http://example.com/file",
                                "tag=img src=http://example.com/file\n",
                                false)
                        .build());
    }

    private class MixedContent {
        private String tag;
        private String att;
        private String value;

        public MixedContent(String tag, String att, String value) {
            super();
            this.tag = tag;
            this.att = att;
            this.value = value;
        }

        public String getTag() {
            return tag;
        }

        public String getAtt() {
            return att;
        }

        public String getValue() {
            return value;
        }
    }
}
