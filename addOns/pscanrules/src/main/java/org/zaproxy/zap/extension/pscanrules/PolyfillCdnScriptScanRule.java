/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.HTMLElementName;
import net.htmlparser.jericho.Source;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

public class PolyfillCdnScriptScanRule extends PluginPassiveScanner
        implements CommonPassiveScanRuleInfo {

    /** Prefix for internationalised messages used by this rule */
    private static final String MESSAGE_PREFIX = "pscanrules.polyfillcdnscript.";

    private static final Map<String, String> ALERT_TAGS =
            CommonAlertTag.toMap(
                    CommonAlertTag.OWASP_2021_A06_VULN_COMP,
                    CommonAlertTag.OWASP_2017_A09_VULN_COMP);

    private static final int PLUGIN_ID = 10115;

    private static Pattern POLYFILL_IO =
            Pattern.compile("http[s]?://.*polyfill\\.io/.*", Pattern.CASE_INSENSITIVE);
    private static Pattern BOOTCSS_COM =
            Pattern.compile("http[s]?://.*bootcss\\.com/.*", Pattern.CASE_INSENSITIVE);
    private static Pattern BOOTCDN_NET =
            Pattern.compile("http[s]?://.*bootcdn\\.net/.*", Pattern.CASE_INSENSITIVE);
    private static Pattern STATICFILE_NET =
            Pattern.compile("http[s]?://.*staticfile\\.net/.*", Pattern.CASE_INSENSITIVE);
    private static Pattern STATICFILE_ORG =
            Pattern.compile("http[s]?://.*staticfile\\.org/.*", Pattern.CASE_INSENSITIVE);
    private static Pattern UNIONADJS_COM =
            Pattern.compile("http[s]?://.*unionadjs\\.com/.*", Pattern.CASE_INSENSITIVE);
    private static Pattern XHSBPZA_COM =
            Pattern.compile("http[s]?://.*xhsbpza\\.com/.*", Pattern.CASE_INSENSITIVE);
    private static Pattern UNION_MACOMS_LA =
            Pattern.compile("http[s]?://.*union\\.macoms\\.la/.*", Pattern.CASE_INSENSITIVE);
    private static Pattern NEWCRBPC_COM =
            Pattern.compile("http[s]?://.*newcrbpc\\.com/.*", Pattern.CASE_INSENSITIVE);

    private static Pattern[] ALL_DOMAINS = {
        POLYFILL_IO,
        BOOTCSS_COM,
        BOOTCDN_NET,
        STATICFILE_NET,
        STATICFILE_ORG,
        UNIONADJS_COM,
        XHSBPZA_COM,
        UNION_MACOMS_LA,
        NEWCRBPC_COM
    };

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        if (msg.getResponseBody().length() > 0 && msg.getResponseHeader().isHtml()) {
            List<Element> sourceElements = source.getAllElements(HTMLElementName.SCRIPT);
            boolean alertRaised = false;
            if (sourceElements != null) {
                for (Element sourceElement : sourceElements) {
                    String src = sourceElement.getAttributeValue("src");
                    if (src != null) {
                        for (Pattern pattern : ALL_DOMAINS) {
                            if (pattern.matcher(src).matches()) {
                                this.createHighConfidenceAlert(src, sourceElement.toString())
                                        .raise();
                                alertRaised = true;
                            }
                        }
                    }
                }
                if (alertRaised) {
                    // Definitely an issue, no point checking the script contents
                    return;
                }
                // Check the script contents, in case they are loading scripts via JS
                for (Element sourceElement : sourceElements) {
                    String contents = sourceElement.getContent().toString();

                    for (Pattern pattern : ALL_DOMAINS) {
                        Matcher matcher = pattern.matcher(contents);
                        if (matcher.find()) {
                            this.createLowConfidenceAlert(null, matcher.group(0)).raise();
                            break;
                        }
                    }
                }
            }
        }
    }

    private AlertBuilder createHighConfidenceAlert(String param, String evidence) {
        return this.createAlert(
                Alert.CONFIDENCE_HIGH,
                Constant.messages.getString(MESSAGE_PREFIX + "desc1"),
                param,
                evidence,
                1);
    }

    private AlertBuilder createLowConfidenceAlert(String param, String evidence) {
        return this.createAlert(
                Alert.CONFIDENCE_LOW,
                Constant.messages.getString(MESSAGE_PREFIX + "desc2"),
                param,
                evidence,
                2);
    }

    private AlertBuilder createAlert(
            int confidence, String description, String param, String evidence, int alertRef) {
        return newAlert()
                .setRisk(getRisk())
                .setConfidence(confidence)
                .setDescription(description)
                .setParam(param)
                .setSolution(Constant.messages.getString(MESSAGE_PREFIX + "soln"))
                .setReference(Constant.messages.getString(MESSAGE_PREFIX + "refs"))
                .setEvidence(evidence)
                .setCweId(829) // CWE Id 829 - Inclusion of Functionality from Untrusted Control
                // Sphere)
                .setWascId(15) // WASC-15: Application Misconfiguration)
                .setAlertRef(PLUGIN_ID + "-" + alertRef);
    }

    @Override
    public List<Alert> getExampleAlerts() {
        return List.of(
                createHighConfidenceAlert(
                                "https://cdn.polyfill.io/malicious.js",
                                "<script type=\"text/javascript\" src=\"https://cdn.polyfill.io/malicious.js\"></script>")
                        .build(),
                createLowConfidenceAlert(
                                "https://cdn.polyfill.io/malicious.js",
                                "<script> script = \"https://cdn.polyfill.io/malicious.js\"; </script>")
                        .build());
    }

    @Override
    public int getPluginId() {
        return PLUGIN_ID;
    }

    public int getRisk() {
        return Alert.RISK_HIGH;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }
}
