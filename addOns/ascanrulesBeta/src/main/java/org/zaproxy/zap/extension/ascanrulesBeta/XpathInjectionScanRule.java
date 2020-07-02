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
package org.zaproxy.zap.extension.ascanrulesBeta;

import java.io.IOException;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.model.Vulnerabilities;
import org.zaproxy.zap.model.Vulnerability;

/**
 * Active scan rule for Xpath Injection testing and verification. WASC Reference:
 * http://projects.webappsec.org/w/page/13247005/XPath%20Injection
 *
 * @author yhawke (2013)
 */
public class XpathInjectionScanRule extends AbstractAppParamPlugin {

    private static final String MESSAGE_PREFIX = "ascanbeta.xpathinjection.";
    private static final int PLUGIN_ID = 90021;

    // Evil payloads able to generate
    // an XML explicit error as described in
    // https://owasp.org/www-community/attacks/XPATH_Injection
    // https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing
    private static final String[] XPATH_PAYLOADS = {"\"'", "<!--", "]]>"};
    // List of XPath errors (need to be improved)
    // Reference W3AF XPath injection plugin
    private static final String[] XPATH_ERRORS = {
        "XPathException",
        "MS.Internal.Xml.",
        "Unknown error in XPath",
        "org.apache.xpath.XPath",
        "A closing bracket expected in",
        "An operand in Union Expression does not produce a node-set",
        "Cannot convert expression to a number",
        "Document Axis does not allow any context Location Steps",
        "Empty Path Expression",
        "Empty Relative Location Path",
        "Empty Union Expression",
        "Expected ')' in",
        "Expected node test or name specification after axis operator",
        "Incompatible XPath key",
        "Incorrect Variable Binding",
        "libxml2 library function failed",
        "libxml2",
        "xmlsec library function",
        "xmlsec",
        "error '80004005'",
        "A document must contain exactly one root element.",
        "<font face=\"Arial\" size=2>Expression must evaluate to a node-set.",
        "Expected token '\\]'",
        "<p>msxml4.dll</font>",
        "<p>msxml3.dll</font>",
        // Lotus notes error when document searching inside nsf files
        "4005 Notes error: Query is not understandable",
        // PHP error
        "SimpleXMLElement::xpath()",
        "xmlXPathEval: evaluation failed",
        "Expression must evaluate to a node-set."
    };

    // Get WASC Vulnerability description
    private static final Vulnerability vuln = Vulnerabilities.getVulnerability("wasc_39");

    // Logger instance
    private static final Logger log = Logger.getLogger(XpathInjectionScanRule.class);

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
        return 643; // CWE-643: Improper Neutralization of Data within XPath Expressions ('XPath
        // Injection');
    }

    @Override
    public int getWascId() {
        return 39;
    }

    @Override
    public int getRisk() {
        return Alert.RISK_HIGH;
    }

    @Override
    public void init() {
        // do nothing
    }

    @Override
    public void scan(HttpMessage msg, String paramName, String value) {
        String originalContent = getBaseMsg().getResponseBody().toString();
        String responseContent;

        // Begin rule execution
        if (log.isDebugEnabled()) {
            log.debug(
                    "Checking ["
                            + msg.getRequestHeader().getMethod()
                            + "]["
                            + msg.getRequestHeader().getURI()
                            + "], parameter ["
                            + paramName
                            + "] for XPath Injection vulnerabilites");
        }

        // Start launching evil payloads
        // -----------------------------
        for (String evilPayload : XPATH_PAYLOADS) {
            msg = getNewMsg();
            setParameter(msg, paramName, evilPayload);

            if (log.isTraceEnabled()) {
                log.trace("Testing [" + paramName + "] = [" + evilPayload + "]");
            }

            try {
                // Send the request and retrieve the response
                sendAndReceive(msg, false);
                responseContent = msg.getResponseBody().toString();

                // Check if the injected content has generated an XML error
                for (String errorString : XPATH_ERRORS) {

                    // if the pattern was found in the new response,
                    // but not in the original response (for the unmodified request)
                    // then we have a match.. XPATH injection!
                    if ((responseContent.contains(errorString))) {

                        // Go to the next, it's a false positive
                        // Done separately because a good choice
                        // could be also to break the loop for this
                        if (originalContent.contains(errorString)) {
                            continue;
                        }

                        // We Found IT!
                        // First do logging
                        if (log.isDebugEnabled()) {
                            log.debug(
                                    "[XPath Injection Found] on parameter ["
                                            + paramName
                                            + "] with payload ["
                                            + evilPayload
                                            + "]");
                        }

                        newAlert()
                                .setConfidence(Alert.CONFIDENCE_HIGH)
                                .setParam(paramName)
                                .setAttack(evilPayload)
                                .setMessage(msg)
                                .raise();

                        // All done. No need to look for vulnerabilities on subsequent
                        // parameters on the same request (to reduce performance impact)
                        return;
                    }
                }

            } catch (IOException ex) {
                // Do not try to internationalise this.. we need an error message in any event..
                // if it's in English, it's still better than not having it at all.
                log.warn(
                        "XPath Injection vulnerability check failed for parameter ["
                                + paramName
                                + "] and payload ["
                                + evilPayload
                                + "] due to an I/O error",
                        ex);
            }

            // Check if the scan has been stopped
            // if yes dispose resources and exit
            if (isStop()) {
                // Dispose all resources
                // Exit the rule
                return;
            }
        }
    }
}
