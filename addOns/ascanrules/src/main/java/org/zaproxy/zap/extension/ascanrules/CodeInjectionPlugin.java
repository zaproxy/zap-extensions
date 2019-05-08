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
package org.zaproxy.zap.extension.ascanrules;

import java.io.IOException;
import java.net.SocketException;
import java.text.MessageFormat;
import java.util.Random;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;

/**
 * Active Plugin for Code Injection testing and verification.
 * https://www.owasp.org/index.php/Code_Injection
 * 
 * @author yhawke (2013)
 */
public class CodeInjectionPlugin extends AbstractAppParamPlugin {

	/**
	 * Prefix for internationalised messages used by this rule
	 */
	private static final String MESSAGE_PREFIX = "ascanrules.codeinjectionplugin.";
	
    // PHP control Token used to verify the vulnerability
    private static final String PHP_CONTROL_TOKEN = "zap_token";
    private static final String PHP_ENCODED_TOKEN = "chr(122).chr(97).chr(112).chr(95).chr(116).chr(111).chr(107).chr(101).chr(110)";
    
    // PHP payloads for Code Injection testing
    // to avoid reflective values mis-interpretation
    // we evaluate the content value inside the response
    // concatenating single ascii characters using the chr function
    // In this way we can avoid some input checking like backslash or apics
    private static final String[] PHP_PAYLOADS = {
        "\";print(" + PHP_ENCODED_TOKEN + ");$var=\"",
        "';print(" + PHP_ENCODED_TOKEN + ");$var='",
        "${@print(" + PHP_ENCODED_TOKEN + ")}",
        "${@print(" + PHP_ENCODED_TOKEN + ")}\\",
        ";print(" + PHP_ENCODED_TOKEN + ");"
    };

    // ASP payloads for Code Injection testing
    // to avoid reflective values mis-interpretation
    // we evaluate the content value inside the response
    // multiplying two random 7-digit numbers
    private static final String[] ASP_PAYLOADS = {
        "\"+response.write([{0}*{1})+\"",
        "'+response.write({0}*{1})+'",
        "response.write({0}*{1})"
    };
    
    // Logger instance
    private static final Logger log 
            = Logger.getLogger(CodeInjectionPlugin.class);
    
    /**
     * Get the unique identifier of this plugin
     * @return this plugin identifier
     */
    @Override
    public int getId() {
        return 90019;    
    }

    /**
     * Get the name of this plugin
     * @return the plugin name
     */
    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }
    
    /**
     * Give back specific plugin dependencies (none for this)
     * @return the list of plugins that need to be executed before
     */
    @Override
    public String[] getDependency() {
        return new String[]{};
    }

    @Override
    public boolean targets(TechSet technologies) {
        if (technologies.includes(Tech.ASP) || technologies.includes(Tech.PHP)) {
            return true;
        }
        return false;
    }

    /**
     * Get the description of the vulnerability when found
     * @return the vulnerability description
     */
    @Override
    public String getDescription() {
        return Constant.messages.getString(MESSAGE_PREFIX + "desc");
    }

    /**
     * Give back the categorization of the vulnerability 
     * checked by this plugin (it's an injection category for CODEi)
     * @return a category from the Category enum list 
     */    
    @Override
    public int getCategory() {
        return Category.INJECTION;
    }

    /**
     * Give back a general solution for the found vulnerability
     * @return the solution that can be put in place
     */
    @Override
    public String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    /**
     * Reports all links and documentation which refers to this vulnerability
     * @return a string based list of references
     */
    @Override
    public String getReference() {
        return Constant.messages.getString(MESSAGE_PREFIX + "refs");
    }

    /**
     * http://cwe.mitre.org/data/definitions/94.html
     * @return the official CWE id
     */
    @Override
    public int getCweId() {
        return 94;
    }

    /**
     * Seems no WASC defined for this
     * @return the official WASC id
     */
    @Override
    public int getWascId() {
        return 20; //WASC-20: Improper Input Handling
    }

    /**
     * Give back the risk associated to this vulnerability (high)
     * @return the risk according to the Alert enum
     */
    @Override
    public int getRisk() {
        return Alert.RISK_HIGH;
    }    

    /**
     * Initialize the plugin according to
     * the overall environment configuration
     */
    @Override
    public void init() {
        // do nothing
    }

    /**
     * Scan for Code Injection Vulnerabilities
     * 
     * @param msg a request only copy of the original message (the response isn't copied)
     * @param paramName the parameter name that need to be exploited
     * @param value the original parameter value
     */
    @Override
    public void scan(HttpMessage msg, String paramName, String value) {

        // Begin plugin execution
        if (log.isDebugEnabled()) {
            log.debug("Checking [" + msg.getRequestHeader().getMethod() + "][" 
                    + msg.getRequestHeader().getURI() 
                    + "], parameter [" + paramName 
                    + "] for Dynamic Code Injection vulnerabilites");
        }

        if (inScope(Tech.PHP)) {
            if (testPhpInjection(paramName)) {
                return;
            }
        }

        if (isStop()) {
            return;
        }

        if (inScope(Tech.ASP)) {
            if (testAspInjection(paramName)) {
                return;
            }
        }
    }

    /**
     * Tests for injection vulnerabilities in PHP code.
     *
     * @param paramName the name of the parameter  will be used for testing for injection
     * @return {@code true} if the vulnerability was found, {@code false} otherwise.
     * @see #PHP_PAYLOADS
     */
    private boolean testPhpInjection(String paramName) {
        for (String phpPayload : PHP_PAYLOADS) {
            HttpMessage msg = getNewMsg();
            setParameter(msg, paramName, phpPayload);

            if (log.isDebugEnabled()) {
                log.debug("Testing [" + paramName + "] = [" + phpPayload + "]");
            }
            
            try {
                // Send the request and retrieve the response
            	try {
            		sendAndReceive(msg, false);
            	} catch (SocketException ex) {
					if (log.isDebugEnabled()) log.debug("Caught " + ex.getClass().getName() + " " + ex.getMessage() + 
							" when accessing: " + msg.getRequestHeader().getURI().toString());
					continue; //Advance in the PHP payload loop, no point continuing on this payload
				} 
                
                // Check if the injected content has been evaluated and printed
                if (msg.getResponseBody().toString().contains(PHP_CONTROL_TOKEN)) {
                    // We Found IT!                     
                    // First do logging
                    if (log.isDebugEnabled()) {
                        log.debug("[PHP Code Injection Found] on parameter [" + paramName 
                                + "] with payload [" + phpPayload + "]");
                    }
                    
                    // Now create the alert message
                    this.bingo(
                            Alert.RISK_HIGH, 
                            Alert.CONFIDENCE_MEDIUM, 
                            Constant.messages.getString(MESSAGE_PREFIX + "name.php"),
                            getDescription(),
                            null,
                            paramName,
                            phpPayload, 
                            null,
                            getSolution(),
                            msg);
                    
                    // All done. No need to look for vulnerabilities on subsequent 
                    // parameters on the same request (to reduce performance impact)
                    return true;
                }

            } catch (IOException ex) {
                //Do not try to internationalise this.. we need an error message in any event..
                //if it's in English, it's still better than not having it at all.
                log.warn("PHP Code Injection vulnerability check failed for parameter ["
                    + paramName + "] and payload [" + phpPayload + "] due to an I/O error", ex);
            }
            
            // Check if the scan has been stopped
            // if yes dispose resources and exit
            if (isStop()) {
                // Dispose all resources
                // Exit the plugin
                break;
            }
        }

        return false;
    }

    /**
     * Tests for injection vulnerabilities in ASP code.
     *
     * @param paramName the name of the parameter that will be used for testing for injection
     * @return {@code true} if the vulnerability was found, {@code false} otherwise.
     * @see #ASP_PAYLOADS
     */
    private boolean testAspInjection(String paramName) {
        Random rand = new Random();
        int bignum1 = 100000 + (int)(rand.nextFloat()*(999999 - 1000000 + 1));
        int bignum2 = 100000 + (int)(rand.nextFloat()*(999999 - 1000000 + 1));
        
        for (String aspPayload : ASP_PAYLOADS) {
            HttpMessage msg = getNewMsg();
            setParameter(msg, paramName, MessageFormat.format(aspPayload, bignum1, bignum2));
            
            if (log.isDebugEnabled()) {
                log.debug("Testing [" + paramName + "] = [" + aspPayload + "]");
            }

            try {
                // Send the request and retrieve the response
            	try {
            		sendAndReceive(msg, false);
            	} catch (SocketException ex) {
					if (log.isDebugEnabled()) log.debug("Caught " + ex.getClass().getName() + " " + ex.getMessage() + 
							" when accessing: " + msg.getRequestHeader().getURI().toString());
					continue; //Advance in the ASP payload loop, no point continuing on this payload
				}
            	
                // Check if the injected content has been evaluated and printed
                if (msg.getResponseBody().toString().contains(Integer.toString(bignum1*bignum2))) {
                    // We Found IT!
                    // First do logging
                    if (log.isDebugEnabled()) {
                        log.debug("[ASP Code Injection Found] on parameter [" + paramName 
                                + "]  with payload [" + aspPayload + "]");
                    }
                    
                    // Now create the alert message
                    this.bingo(
                            Alert.RISK_HIGH, 
                            Alert.CONFIDENCE_MEDIUM, 
                            Constant.messages.getString(MESSAGE_PREFIX + "name.asp"),
                            getDescription(),
                            null,
                            paramName,
                            aspPayload, 
                            null,
                            getSolution(),
                            msg);
                    return true;
                }

            } catch (IOException ex) {
                //Do not try to internationalise this.. we need an error message in any event..
                //if it's in English, it's still better than not having it at all.
                log.warn("ASP Code Injection vulnerability check failed for parameter ["
                    + paramName + "] and payload [" + aspPayload + "] due to an I/O error", ex);
            }
            
            // Check if the scan has been stopped
            // if yes dispose resources and exit
            if (isStop()) {
                // Dispose all resources
                // Exit the plugin
                break;
            }
        }       

        return false;
    }
}
