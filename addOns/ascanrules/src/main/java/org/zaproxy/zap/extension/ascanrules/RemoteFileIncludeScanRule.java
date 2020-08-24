/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2013 The ZAP Development Team
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
package org.zaproxy.zap.extension.ascanrules;

import static org.zaproxy.zap.extension.ascanrules.utils.Constants.NULL_BYTE_CHARACTER;

import java.net.UnknownHostException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.zap.model.Vulnerabilities;
import org.zaproxy.zap.model.Vulnerability;

/** a scanner that looks for Remote File Include vulnerabilities */
public class RemoteFileIncludeScanRule extends AbstractAppParamPlugin {

    /** Prefix for internationalised messages used by this rule */
    private static final String MESSAGE_PREFIX = "ascanrules.remotefileinclude.";

    /** the various prefixes to try, for each of the remote file targets below */
    private static final String[] REMOTE_FILE_TARGET_PREFIXES = {
        "http://",
        "",
        "HTTP://",
        "https://",
        "HTTPS://",
        "HtTp://",
        "HtTpS://",
        // Null Byte payload, incase validator for the remote file inclusion is
        // vulnerable to null byte i.e. say validator is written in C/C++ where Null
        // character marks end of string then that validator will not read characters
        // after null byte hence validation can be bypassed and if url is invoked by trimming null
        // bytes then it will cause RFI
        NULL_BYTE_CHARACTER + "http://",
        NULL_BYTE_CHARACTER + "",
        NULL_BYTE_CHARACTER + "HTTP://",
        NULL_BYTE_CHARACTER + "https://",
        NULL_BYTE_CHARACTER + "HTTPS://",
        NULL_BYTE_CHARACTER + "HtTp://",
        NULL_BYTE_CHARACTER + "HtTpS://",
    };
    /** the various local file targets to look for (prefixed by the prefixes above) */
    private static final String[] REMOTE_FILE_TARGETS = {
        "www.google.com/",
        "www.google.com:80/",
        "www.google.com",
        "www.google.com/search?q=OWASP%20ZAP",
        "www.google.com:80/search?q=OWASP%20ZAP",
    };
    /** the patterns to look for, associated with the equivalent remote file targets above */
    private static final Pattern[] REMOTE_FILE_PATTERNS = {
        Pattern.compile("<title>Google</title>"),
        Pattern.compile("<title>Google</title>"),
        Pattern.compile("<title>Google</title>"),
        Pattern.compile("<title.*?Google.*?/title>"),
        Pattern.compile("<title.*?Google.*?/title>"),
    };
    /** The number of requests we will send per parameter, based on the attack strength */
    private static final int REQ_PER_PARAM_OFF = 0;

    private static final int REQ_PER_PARAM_LOW = 1;
    private static final int REQ_PER_PARAM_MEDIUM = 2;
    private static final int REQ_PER_PARAM_HIGH = 4;
    private static final int REQ_PER_PARAM_INSANE = REMOTE_FILE_TARGET_PREFIXES.length;
    /** details of the vulnerability which we are attempting to find */
    private static Vulnerability vuln = Vulnerabilities.getVulnerability("wasc_5");
    /** the logger object */
    private static Logger log = Logger.getLogger(RemoteFileIncludeScanRule.class);

    @Override
    public int getId() {
        return 7;
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
        return Category.SERVER;
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
    public void scan(HttpMessage msg, String param, String value) {

        try {
            // figure out how aggressively we should test
            // this will be measured in the number of requests we send for each parameter
            int prefixCountRFI = 0;

            // DEBUG only
            // this.setAttackStrength(AttackStrength.INSANE);

            if (log.isDebugEnabled()) {
                log.debug("Attacking at Attack Strength: " + this.getAttackStrength());
            }
            String origResponse =
                    msg.getResponseHeader().toString() + msg.getResponseBody().toString();

            // Set number of prefixes to check on the remote file names
            switch (this.getAttackStrength()) {
                case LOW:
                    prefixCountRFI = REQ_PER_PARAM_LOW;
                    break;

                case MEDIUM:
                    prefixCountRFI = REQ_PER_PARAM_MEDIUM;
                    break;

                case HIGH:
                    prefixCountRFI = REQ_PER_PARAM_HIGH;
                    break;

                case INSANE:
                    prefixCountRFI = REQ_PER_PARAM_INSANE;
                    break;

                default:
                    prefixCountRFI = REQ_PER_PARAM_OFF;
                    break;
            }

            Matcher matcher;
            Matcher origMatcher;

            if (log.isDebugEnabled()) {
                log.debug(
                        "Checking ["
                                + getBaseMsg().getRequestHeader().getMethod()
                                + "] ["
                                + getBaseMsg().getRequestHeader().getURI()
                                + "], parameter ["
                                + param
                                + "] for Path Traversal to remote files");
            }

            // for each prefix in turn
            for (int h = 0; h < prefixCountRFI; h++) {
                String prefix = REMOTE_FILE_TARGET_PREFIXES[h];

                // for each target in turn
                for (int i = 0; i < REMOTE_FILE_TARGETS.length; i++) {
                    String target = REMOTE_FILE_TARGETS[i];

                    // get a new copy of the original message (request only) for each parameter
                    // value to try
                    msg = getNewMsg();
                    setParameter(msg, param, prefix + target);

                    // send the modified request, and see what we get back
                    try {
                        sendAndReceive(msg);
                    } catch (IllegalStateException | UnknownHostException ex) {
                        if (log.isDebugEnabled())
                            log.debug(
                                    "Caught "
                                            + ex.getClass().getName()
                                            + " "
                                            + ex.getMessage()
                                            + " when accessing: "
                                            + msg.getRequestHeader().getURI().toString());
                        continue; // Something went wrong, continue to the next target in the loop
                    }

                    // does it match the pattern specified for that file name?
                    String response =
                            msg.getResponseHeader().toString() + msg.getResponseBody().toString();
                    matcher = REMOTE_FILE_PATTERNS[i].matcher(response);
                    // if the output matches, and we get a 200
                    if (matcher.find()
                            && msg.getResponseHeader().getStatusCode() == HttpStatusCode.OK) {
                        // And check that this isnt exactly the same as the original response
                        origMatcher = REMOTE_FILE_PATTERNS[i].matcher(origResponse);
                        if (origMatcher.find() && origMatcher.group().equals(matcher.group())) {
                            // Its the same as before
                            log.debug(
                                    "Not reporting alert - same title as original: "
                                            + matcher.group());
                        } else {
                            newAlert()
                                    .setConfidence(Alert.CONFIDENCE_MEDIUM)
                                    .setParam(param)
                                    .setAttack(prefix + target)
                                    .setEvidence(matcher.group())
                                    .setMessage(msg)
                                    .raise();
                            // All done. No need to look for vulnerabilities on subsequent
                            // parameters on the same request (to reduce performance impact)
                            return;
                        }
                    }

                    // Check if the scan has been stopped
                    // if yes dispose resources and exit
                    if (isStop()) {
                        // Dispose all resources
                        // Exit the scan rule
                        return;
                    }
                }
            }

        } catch (Exception e) {
            if (log.isDebugEnabled()) {
                log.debug(
                        "Error checking ["
                                + getBaseMsg().getRequestHeader().getMethod()
                                + "] ["
                                + getBaseMsg().getRequestHeader().getURI()
                                + "], parameter ["
                                + param
                                + "] for Remote File Include. "
                                + e.getMessage());
            }
        }
    }

    @Override
    public int getRisk() {
        return Alert.RISK_HIGH;
    }

    @Override
    public int getCweId() {
        return 98;
    }

    @Override
    public int getWascId() {
        return 5;
    }
}
