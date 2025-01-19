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
import java.util.Locale;
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

    private static final String START_P = "http[s]?://.*";
    private static final String END_P = ".*\\w";

    private static final String POLYFILL_IO = "polyfill.io/";
    private static final String BOOTCSS_COM = "bootcss.com/";
    private static final String BOOTCDN_NET = "bootcdn.net/";
    private static final String STATICFILE_NET = "staticfile.net/";
    private static final String STATICFILE_ORG = "staticfile.org/";
    private static final String UNIONADJS_COM = "unionadjs.com/";
    private static final String XHSBPZA_COM = "xhsbpza.com/";
    private static final String UNION_MACOMS_LA = "union.macoms.la/";
    private static final String NEWCRBPC_COM = "newcrbpc.com/";

    private static final Pattern POLYFILL_IO_URL =
            Pattern.compile(START_P + POLYFILL_IO + END_P, Pattern.CASE_INSENSITIVE);
    private static final Pattern BOOTCSS_COM_URL =
            Pattern.compile(START_P + BOOTCSS_COM + END_P, Pattern.CASE_INSENSITIVE);
    private static final Pattern BOOTCDN_NET_URL =
            Pattern.compile(START_P + BOOTCDN_NET + END_P, Pattern.CASE_INSENSITIVE);
    private static final Pattern STATICFILE_NET_URL =
            Pattern.compile(START_P + STATICFILE_NET + END_P, Pattern.CASE_INSENSITIVE);
    private static final Pattern STATICFILE_ORG_URL =
            Pattern.compile(START_P + STATICFILE_ORG + END_P, Pattern.CASE_INSENSITIVE);
    private static final Pattern UNIONADJS_COM_URL =
            Pattern.compile(START_P + UNIONADJS_COM + END_P, Pattern.CASE_INSENSITIVE);
    private static final Pattern XHSBPZA_COM_URL =
            Pattern.compile(START_P + XHSBPZA_COM + END_P, Pattern.CASE_INSENSITIVE);
    private static final Pattern UNION_MACOMS_LA_URL =
            Pattern.compile(START_P + UNION_MACOMS_LA + END_P, Pattern.CASE_INSENSITIVE);
    private static final Pattern NEWCRBPC_COM_URL =
            Pattern.compile(START_P + NEWCRBPC_COM + END_P, Pattern.CASE_INSENSITIVE);

    private static final String[] ALL_DOMAINS = {
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

    private static final Pattern[] ALL_DOMAIN_URLS = {
        POLYFILL_IO_URL,
        BOOTCSS_COM_URL,
        BOOTCDN_NET_URL,
        STATICFILE_NET_URL,
        STATICFILE_ORG_URL,
        UNIONADJS_COM_URL,
        XHSBPZA_COM_URL,
        UNION_MACOMS_LA_URL,
        NEWCRBPC_COM_URL
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
                        for (Pattern pattern : ALL_DOMAIN_URLS) {
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
                    String contentsLc = contents.toLowerCase(Locale.ROOT);

                    for (int i = 0; i < ALL_DOMAINS.length; i++) {
                        String domain = ALL_DOMAINS[i];
                        // Use "contains" first as it makes a huge difference in speed
                        if (contentsLc.contains(domain)) {
                            Pattern pattern = ALL_DOMAIN_URLS[i];
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
                .setRisk(Alert.RISK_HIGH)
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

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }
}
