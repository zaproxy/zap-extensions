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
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.HTMLElementName;
import net.htmlparser.jericho.Source;
import net.htmlparser.jericho.StartTagType;
import net.htmlparser.jericho.Tag;
import org.antlr.v4.runtime.CharStreams;
import org.antlr.v4.runtime.Lexer;
import org.antlr.v4.runtime.Token;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.addon.commonlib.ResourceIdentificationUtils;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;
import org.zaproxy.zap.extension.pscanrules.antlr.JavaScriptLexer;

public class InformationDisclosureSuspiciousCommentsScanRule extends PluginPassiveScanner
        implements CommonPassiveScanRuleInfo {

    private static final String MESSAGE_PREFIX =
            "pscanrules.informationdisclosuresuspiciouscomments.";
    private static final int PLUGIN_ID = 10027;

    private static final Map<String, String> ALERT_TAGS;

    static {
        Map<String, String> alertTags =
                new HashMap<>(
                        CommonAlertTag.toMap(
                                CommonAlertTag.OWASP_2021_A01_BROKEN_AC,
                                CommonAlertTag.OWASP_2017_A03_DATA_EXPOSED,
                                CommonAlertTag.WSTG_V42_INFO_05_CONTENT_LEAK));
        alertTags.put(PolicyTag.PENTEST.getTag(), "");
        ALERT_TAGS = Collections.unmodifiableMap(alertTags);
    }

    private static final int MAX_ELEMENT_CHRS_TO_REPORT = 128;

    public static final String CUSTOM_PAYLOAD_CATEGORY = "Suspicious-Comments";
    public static final List<String> DEFAULT_PAYLOADS =
            List.of(
                    "TODO",
                    "FIXME",
                    "BUG",
                    "BUGS",
                    "XXX",
                    "QUERY",
                    "DB",
                    "ADMIN",
                    "ADMINISTRATOR",
                    "USER",
                    "USERNAME",
                    "SELECT",
                    "WHERE",
                    "FROM",
                    "LATER",
                    "DEBUG");

    private static final Supplier<Iterable<String>> DEFAULT_PAYLOAD_PROVIDER =
            () -> DEFAULT_PAYLOADS;

    private static Supplier<Iterable<String>> payloadProvider = DEFAULT_PAYLOAD_PROVIDER;

    private List<Pattern> patterns = null;

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {

        patterns = getPatterns();
        Map<String, List<AlertSummary>> alertMap = new HashMap<>();

        if (msg.getResponseBody().length() > 0
                && msg.getResponseHeader().isText()
                && !ResourceIdentificationUtils.isFont(msg)) {

            if (ResourceIdentificationUtils.isJavaScript(msg)) {
                checkJsComments(patterns, alertMap, msg.getResponseBody().toString());
            } else {
                // Can use the parser

                // Check the comments
                source.fullSequentialParse(); // Needed to check parent
                List<Tag> tags = source.getAllTags(StartTagType.COMMENT);
                for (Tag tag : tags) {
                    Element element = tag.getElement();
                    Element parent = element != null ? element.getParentElement() : null;
                    if (parent != null && HTMLElementName.SCRIPT.equals(parent.getName())) {
                        continue; // Skip HTML comments inside script blocks
                    }
                    searchSuspiciousComments(alertMap, tag.toString());
                }
                // Check the scripts
                Element el;
                int offset = 0;
                while ((el = source.getNextElement(offset, HTMLElementName.SCRIPT)) != null) {
                    checkJsComments(patterns, alertMap, el.getContent().toString());
                    offset = el.getEnd();
                }
            }
        }

        // Only raise one alert for each pattern detected, giving a total count if > 1 instance
        for (Entry<String, List<AlertSummary>> entry : alertMap.entrySet()) {
            String other;
            AlertSummary firstSummary = entry.getValue().get(0);
            if (entry.getValue().size() == 1) {
                other =
                        Constant.messages.getString(
                                MESSAGE_PREFIX + "otherinfo",
                                firstSummary.getPattern(),
                                truncateString(firstSummary.getDetail()));
            } else {
                other =
                        Constant.messages.getString(
                                MESSAGE_PREFIX + "otherinfo2",
                                firstSummary.getPattern(),
                                truncateString(firstSummary.getDetail()),
                                entry.getValue().size());
            }
            this.createAlert(other, firstSummary.getEvidence()).raise();
        }
    }

    private void checkJsComments(
            List<Pattern> patterns, Map<String, List<AlertSummary>> alertMap, String target) {
        if (!isGoodCandidate(target)) {
            return;
        }

        JavaScriptLexer lexer = new JavaScriptLexer(CharStreams.fromString(target));
        Token token;

        do {
            token = lexer.nextToken();
            if (token.getChannel() == Lexer.HIDDEN
                    && (token.getType() == JavaScriptLexer.MultiLineComment
                            || token.getType() == JavaScriptLexer.SingleLineComment
                            || token.getType() == JavaScriptLexer.HtmlComment)) {
                searchSuspiciousComments(alertMap, token.getText());
            }
        } while (token.getType() != Token.EOF);
    }

    private void searchSuspiciousComments(
            Map<String, List<AlertSummary>> alertMap, String comment) {
        for (Pattern pattern : patterns) {
            Matcher m = pattern.matcher(comment);
            if (m.find()) {
                recordAlertSummary(
                        alertMap, new AlertSummary(pattern.toString(), comment, m.group()));
                return; // Only need to record this comment once
            }
        }
    }

    private static boolean isGoodCandidate(String target) {
        return target.contains("//") || target.contains("/*");
    }

    private static void recordAlertSummary(
            Map<String, List<AlertSummary>> alertMap, AlertSummary summary) {
        alertMap.computeIfAbsent(summary.getPattern(), k -> new ArrayList<>()).add(summary);
    }

    private static String truncateString(String str) {
        if (str.length() > MAX_ELEMENT_CHRS_TO_REPORT) {
            return str.substring(0, MAX_ELEMENT_CHRS_TO_REPORT);
        }
        return str;
    }

    private AlertBuilder createAlert(String detail, String evidence) {
        return newAlert()
                .setRisk(Alert.RISK_INFO)
                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                .setDescription(Constant.messages.getString(MESSAGE_PREFIX + "desc"))
                .setOtherInfo(detail)
                .setSolution(Constant.messages.getString(MESSAGE_PREFIX + "soln"))
                // CWE-615: Inclusion of Sensitive Information in Source Code Comments
                .setCweId(615)
                .setWascId(13) // WASC Id - Info leakage
                .setEvidence(evidence);
    }

    private List<Pattern> getPatterns() {
        if (patterns == null) {
            patterns = initPatterns();
        }
        return patterns;
    }

    private static List<Pattern> initPatterns() {
        List<Pattern> targetPatterns = new ArrayList<>();
        for (String payload : payloadProvider.get()) {
            targetPatterns.add(compilePayload(payload));
        }
        return targetPatterns;
    }

    private static Pattern compilePayload(String payload) {
        return Pattern.compile("\\b" + payload + "\\b", Pattern.CASE_INSENSITIVE);
    }

    public static void setPayloadProvider(Supplier<Iterable<String>> provider) {
        payloadProvider = provider == null ? DEFAULT_PAYLOAD_PROVIDER : provider;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    @Override
    public int getPluginId() {
        return PLUGIN_ID;
    }

    @Override
    public List<Alert> getExampleAlerts() {
        Alert example =
                createAlert(
                                Constant.messages.getString(
                                        MESSAGE_PREFIX + "otherinfo",
                                        "\\bFIXME\\b",
                                        "<!-- FixMe: cookie: root=true; Secure -->"),
                                "FixMe")
                        .build();
        example.setTags(
                CommonAlertTag.mergeTags(example.getTags(), CommonAlertTag.CUSTOM_PAYLOADS));
        return List.of(example);
    }

    private static class AlertSummary {
        private final String pattern;
        private final String detail;
        private final String evidence;

        public AlertSummary(String pattern, String detail, String evidence) {
            super();
            this.pattern = pattern;
            this.detail = detail;
            this.evidence = evidence;
        }

        public String getPattern() {
            return pattern;
        }

        public String getDetail() {
            return detail;
        }

        public String getEvidence() {
            return evidence;
        }
    }
}
