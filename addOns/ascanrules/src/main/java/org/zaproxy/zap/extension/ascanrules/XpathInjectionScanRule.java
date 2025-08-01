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

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Supplier;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.addon.commonlib.vulnerabilities.Vulnerabilities;
import org.zaproxy.addon.commonlib.vulnerabilities.Vulnerability;

/**
 * Active scan rule for Xpath Injection testing and verification. WASC Reference:
 * http://projects.webappsec.org/w/page/13247005/XPath%20Injection
 *
 * @author yhawke (2013)
 */
public class XpathInjectionScanRule extends AbstractAppParamPlugin
        implements CommonActiveScanRuleInfo {

    private static final String MESSAGE_PREFIX = "ascanrules.xpathinjection.";
    private static final int PLUGIN_ID = 90021;

    // Evil payloads able to generate
    // an XML explicit error as described in
    // https://owasp.org/www-community/attacks/XPATH_Injection
    // https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing
    private static final String[] XPATH_PAYLOADS = {"\"'", "<!--", "]]>"};
    // List of XPath errors (need to be improved)
    // Reference W3AF XPath injection plugin
    private static final List<String> DEFAULT_ERRORS =
            List.of(
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
                    "Expression must evaluate to a node-set.");

    public static final List<String> DEFAULT_DISABLED_ERRORS =
            List.of("Error: javax.xml.transform.TransformerException");

    private static final Supplier<Iterable<String>> DEFAULT_ERROR_PROVIDER = List::of;
    private static Supplier<Iterable<String>> errorProvider = DEFAULT_ERROR_PROVIDER;

    public static final String ERRORS_PAYLOAD_CATEGORY = "XPath-Errors";

    private static final Map<String, String> ALERT_TAGS;

    static {
        Map<String, String> alertTags =
                new HashMap<>(
                        CommonAlertTag.toMap(
                                CommonAlertTag.OWASP_2021_A03_INJECTION,
                                CommonAlertTag.OWASP_2017_A01_INJECTION,
                                CommonAlertTag.WSTG_V42_INPV_09_XPATH,
                                CommonAlertTag.HIPAA,
                                CommonAlertTag.PCI_DSS,
                                CommonAlertTag.CUSTOM_PAYLOADS));
        alertTags.put(PolicyTag.API.getTag(), "");
        alertTags.put(PolicyTag.DEV_CICD.getTag(), "");
        alertTags.put(PolicyTag.DEV_STD.getTag(), "");
        alertTags.put(PolicyTag.DEV_FULL.getTag(), "");
        alertTags.put(PolicyTag.QA_STD.getTag(), "");
        alertTags.put(PolicyTag.QA_FULL.getTag(), "");
        alertTags.put(PolicyTag.SEQUENCE.getTag(), "");
        alertTags.put(PolicyTag.PENTEST.getTag(), "");
        ALERT_TAGS = Collections.unmodifiableMap(alertTags);
    }

    // Get WASC Vulnerability description
    private static final Vulnerability VULN = Vulnerabilities.getDefault().get("wasc_39");

    // Logger instance
    private static final Logger LOGGER = LogManager.getLogger(XpathInjectionScanRule.class);

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
        return VULN.getDescription();
    }

    @Override
    public int getCategory() {
        return Category.INJECTION;
    }

    @Override
    public String getSolution() {
        return VULN.getSolution();
    }

    @Override
    public String getReference() {
        return VULN.getReferencesAsString();
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
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
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
        LOGGER.debug(
                "Checking [{}] [{}], parameter [{}] for XPath Injection vulnerabilities.",
                msg.getRequestHeader().getMethod(),
                msg.getRequestHeader().getURI(),
                paramName);

        // Start launching evil payloads
        // -----------------------------
        for (String evilPayload : XPATH_PAYLOADS) {
            msg = getNewMsg();
            setParameter(msg, paramName, evilPayload);

            LOGGER.trace("Testing [{}] = [{}]", paramName, evilPayload);

            try {
                // Send the request and retrieve the response
                sendAndReceive(msg, false);
                responseContent = msg.getResponseBody().toString();

                Iterator<String> errors =
                        new IteratorJoin<>(
                                DEFAULT_ERRORS.iterator(), getErrorProvider().get().iterator());
                // Check if the injected content has generated an XML error
                while (errors.hasNext()) {
                    String errorString = errors.next();
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
                        LOGGER.debug(
                                "[XPath Injection Found] on parameter [{}] with payload [{}]",
                                paramName,
                                evilPayload);

                        createAlert(paramName, evilPayload, errorString).setMessage(msg).raise();

                        // All done. No need to look for vulnerabilities on subsequent
                        // parameters on the same request (to reduce performance impact)
                        return;
                    }
                }

            } catch (IOException ex) {
                // Do not try to internationalise this.. we need an error message in any event..
                // if it's in English, it's still better than not having it at all.
                LOGGER.warn(
                        "XPath Injection vulnerability check failed for parameter [{}] and payload [{}] due to an I/O error.",
                        paramName,
                        evilPayload,
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

    private AlertBuilder createAlert(String param, String payload, String evidence) {
        return newAlert()
                .setConfidence(Alert.CONFIDENCE_HIGH)
                .setParam(param)
                .setAttack(payload)
                .setEvidence(evidence);
    }

    @Override
    public List<Alert> getExampleAlerts() {
        return List.of(createAlert("foo", XPATH_PAYLOADS[0], DEFAULT_ERRORS.get(0)).build());
    }

    static Supplier<Iterable<String>> getErrorProvider() {
        return errorProvider;
    }

    public static void setErrorProvider(Supplier<Iterable<String>> provider) {
        errorProvider = provider == null ? DEFAULT_ERROR_PROVIDER : provider;
    }

    private static class IteratorJoin<T> implements Iterator<T> {

        private final Iterator<T> next;
        private Iterator<T> current;

        IteratorJoin(Iterator<T> first, Iterator<T> next) {
            this.next = Objects.requireNonNull(next);
            current = Objects.requireNonNull(first);
        }

        @Override
        public boolean hasNext() {
            if (current == null) {
                return false;
            }

            if (current.hasNext()) {
                return true;
            }

            if (current == next) {
                current = null;
                return false;
            }

            current = next;
            return current.hasNext();
        }

        @Override
        public T next() {
            return current.next();
        }
    }
}
