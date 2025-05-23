/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2019 The ZAP Development Team
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

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.HTMLElementName;
import net.htmlparser.jericho.Source;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/** A class to passively scan responses for indications that this is a modern web application. */
public class ModernAppDetectionScanRule extends PluginPassiveScanner
        implements CommonPassiveScanRuleInfo {

    /** Prefix for internationalized messages used by this rule */
    private static final String MESSAGE_PREFIX = "pscanrules.modernapp.";

    private static final Map<String, String> ALERT_TAGS;

    static {
        Map<String, String> alertTags = new HashMap<>();
        alertTags.put(PolicyTag.PENTEST.getTag(), "");
        alertTags.put(PolicyTag.DEV_STD.getTag(), "");
        alertTags.put(PolicyTag.QA_STD.getTag(), "");
        ALERT_TAGS = Collections.unmodifiableMap(alertTags);
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        if (!msg.getResponseHeader().isHtml()) {
            // Only check HTML responses
            return;
        }
        String evidence = null;
        String otherInfo = null;

        List<Element> links = source.getAllElements(HTMLElementName.A);
        if (links.isEmpty()) {
            // if no links but there are scripts then thats another indication
            List<Element> scripts = source.getAllElements(HTMLElementName.SCRIPT);
            if (scripts.size() > 0) {
                evidence = scripts.get(0).toString();
                otherInfo = Constant.messages.getString(MESSAGE_PREFIX + "other.nolinks");
            }
        } else {
            // check all of the links
            for (Element link : links) {
                String href = link.getAttributeValue("href");
                if (href == null || href.length() == 0 || href.equals("#")) {
                    evidence = link.toString();
                    otherInfo = Constant.messages.getString(MESSAGE_PREFIX + "other.links");
                    break;
                }
                String target = link.getAttributeValue("target");
                if (target != null && target.equals("_self")) {
                    evidence = link.toString();
                    otherInfo = Constant.messages.getString(MESSAGE_PREFIX + "other.self");
                    break;
                }
            }
        }
        if (evidence == null) {
            Element noScript = source.getFirstElement(HTMLElementName.NOSCRIPT);
            if (noScript != null) {
                // Its an indication the app works differently with JavaScript
                evidence = noScript.toString();
                otherInfo = Constant.messages.getString(MESSAGE_PREFIX + "other.noscript");
            }
        }

        if (evidence != null && evidence.length() > 0) {
            // we found something
            buildAlert(otherInfo, evidence).raise();
        }
    }

    private AlertBuilder buildAlert(String otherInfo, String evidence) {
        return newAlert()
                .setRisk(Alert.RISK_INFO)
                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                .setDescription(Constant.messages.getString(MESSAGE_PREFIX + "desc"))
                .setOtherInfo(otherInfo)
                .setSolution(Constant.messages.getString(MESSAGE_PREFIX + "soln"))
                .setEvidence(evidence);
    }

    @Override
    public int getPluginId() {
        return 10109;
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    @Override
    public List<Alert> getExampleAlerts() {
        return List.of(
                buildAlert(
                                Constant.messages.getString(MESSAGE_PREFIX + "other.self"),
                                "<a href=\"link\" target=\"_self\">Link</a>")
                        .build());
    }
}
