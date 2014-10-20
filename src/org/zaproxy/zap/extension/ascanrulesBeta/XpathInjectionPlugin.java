/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
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
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.model.Vulnerabilities;
import org.zaproxy.zap.model.Vulnerability;

/**
 * Active Plugin for Xpath Injection testing and verification. WASC Reference:
 * http://projects.webappsec.org/w/page/13247005/XPath%20Injection
 *
 * @author yhawke (2013)
 */
public class XpathInjectionPlugin extends AbstractAppParamPlugin {

    // Evil payloads able to generate 
    // an XML explicit error as described in
    // https://www.owasp.org/index.php/Testing_for_XML_Injection
    private static final String[] XPATH_PAYLOADS = {
        "\"'",
        "<!--",
        "]]>"
    };
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
        "SimpleXMLElement::xpath()" // PHP error
    };
    
    // Get WASC Vulnerability description
    private static final Vulnerability vuln 
            = Vulnerabilities.getVulnerability("wasc_39");
    
    // Logger instance
    private static final Logger log 
            = Logger.getLogger(XpathInjectionPlugin.class);

    /**
     * Get the unique identifier of this plugin
     *
     * @return this plugin identifier
     */
    @Override
    public int getId() {
        return 90021;
    }

    /**
     * Get the name of this plugin
     *
     * @return the plugin name
     */
    @Override
    public String getName() {
        return "XPath Injection Plugin";
    }

    /**
     * Give back specific pugin dependancies (none for this)
     *
     * @return the list of plugins that need to be executed before
     */
    @Override
    public String[] getDependency() {
        return new String[]{};
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
     * Give back the categorization of the vulnerability checked by this plugin
     * (it's an injection category for CODEi)
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
     * http://cwe.mitre.org/data/definitions/91.html
     *
     * @return the official CWE id
     */
    @Override
    public int getCweId() {
        // I'm not sure mapping is correct 
        // (it refers to general XML injection)
        return 91;
    }

    /**
     * http://projects.webappsec.org/w/page/13247005/XPath%20Injection
     *
     * @return the official WASC id
     */
    @Override
    public int getWascId() {
        return 39;
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

    /**
     * Initialize the plugin according to the overall environment configuration
     */
    @Override
    public void init() {
        // do nothing
    }

    /**
     * Scan for Xpath Injection Vulnerabilites.
     *
     * @param msg a request only copy of the original message (the response
     * isn't copied)
     * @param parameter the parameter name that need to be exploited
     * @param value the original parameter value
     */
    @Override
    public void scan(HttpMessage msg, String paramName, String value) {
        String originalContent = getBaseMsg().getResponseBody().toString();
        String responseContent;

        // Begin plugin execution
        if (log.isDebugEnabled()) {
            log.debug("Checking [" + msg.getRequestHeader().getMethod() + "]["
                    + msg.getRequestHeader().getURI()
                    + "], parameter [" + paramName
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
                        log.info("[XPath Injection Found] on parameter [" + paramName
                                + "] with payload [" + evilPayload + "]");

                        // Now create the alert message
                        this.bingo(
                                Alert.RISK_HIGH,
                                Alert.WARNING,
                                getName() + " - XPath Injection",
                                getDescription(),
                                null,
                                paramName,
                                evilPayload,
                                null,
                                getSolution(),
                                msg);

                        // All done. No need to look for vulnerabilities on subsequent 
                        // parameters on the same request (to reduce performance impact)
                        return;
                    }
                }
                
            } catch (IOException ex) {
                //Do not try to internationalise this.. we need an error message in any event..
                //if it's in English, it's still better than not having it at all.
                log.error("XPath Injection vulnerability check failed for parameter ["
                        + paramName + "] and payload [" + evilPayload + "] due to an I/O error", ex);
            }
            
            // Check if the scan has been stopped
            // if yes dispose resources and exit
            if (isStop()) {
                // Dispose all resources
                // Exit the plugin
                return;
            }
        }
    }
}
