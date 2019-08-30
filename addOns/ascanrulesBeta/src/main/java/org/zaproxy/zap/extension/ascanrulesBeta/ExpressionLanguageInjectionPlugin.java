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
import java.net.UnknownHostException;
import java.util.Random;
import org.apache.commons.httpclient.InvalidRedirectLocationException;
import org.apache.commons.httpclient.URIException;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;

/**
 * CWE-917: Improper Neutralization of Special Elements used in an Expression Language Statement
 * ('Expression Language Injection')
 *
 * <p>http://cwe.mitre.org/data/definitions/917.html
 *
 * @author yhawke (2014)
 */
public class ExpressionLanguageInjectionPlugin extends AbstractAppParamPlugin {

    // Logger object
    private static final Logger log = Logger.getLogger(ExpressionLanguageInjectionPlugin.class);

    private static final int MAX_NUM_TRIES = 1000;
    private static final int DEVIATION_VALUE = 999999;
    private static final int MEAN_VALUE = 100000;

    /**
     * Get the unique identifier of this plugin
     *
     * @return this plugin identifier
     */
    @Override
    public int getId() {
        return 90025;
    }

    /**
     * Get the name of this plugin
     *
     * @return the plugin name
     */
    @Override
    public String getName() {
        return Constant.messages.getString("ascanbeta.elinjection.name");
    }

    /**
     * Get the description of the vulnerbaility when found
     *
     * @return the vulnerability description
     */
    @Override
    public String getDescription() {
        return Constant.messages.getString("ascanbeta.elinjection.desc");
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
        return Constant.messages.getString("ascanbeta.elinjection.soln");
    }

    @Override
    public String getReference() {
        return Constant.messages.getString("ascanbeta.elinjection.refs");
    }

    /**
     * http://cwe.mitre.org/data/definitions/917.html
     *
     * @return the official CWE id
     */
    @Override
    public int getCweId() {
        return 917;
    }

    /** @return the official WASC id */
    @Override
    public int getWascId() {
        // There's not a real classification for this
        // so we consider the general "Improper Input Handling" class
        // http://projects.webappsec.org/w/page/13246933/Improper%20Input%20Handling
        return 20;
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

    /** Initialize the plugin according to the overall environment configuration */
    @Override
    public void init() {
        // do nothing
    }

    /**
     * Scan for Expression Language Injection Vulnerabilites
     *
     * @param msg a request only copy of the original message (the response isn't copied)
     * @param paramName the parameter name that need to be exploited
     * @param value the original parameter value
     */
    @Override
    public void scan(HttpMessage msg, String paramName, String value) {

        String originalContent = getBaseMsg().getResponseBody().toString();
        Random rand = new Random();
        String addedString;
        int bignum1;
        int bignum2;
        int tries = 0;

        do {
            bignum1 = MEAN_VALUE + (int) (rand.nextFloat() * (DEVIATION_VALUE - MEAN_VALUE + 1));
            bignum2 = MEAN_VALUE + (int) (rand.nextFloat() * (DEVIATION_VALUE - MEAN_VALUE + 1));
            addedString = String.valueOf(bignum1 + bignum2);
            tries++;

        } while (originalContent.contains(addedString) && (tries < MAX_NUM_TRIES));

        // Build the evil payload ${100146+99273}
        String payload = "${" + bignum1 + "+" + bignum2 + "}";

        try {
            // Set the expression value
            setParameter(msg, paramName, payload);
            try {
                // Send the request and retrieve the response
                sendAndReceive(msg);
            } catch (InvalidRedirectLocationException
                    | URIException
                    | UnknownHostException
                    | IllegalArgumentException ex) {
                if (log.isDebugEnabled())
                    log.debug(
                            "Caught "
                                    + ex.getClass().getName()
                                    + " "
                                    + ex.getMessage()
                                    + " when accessing: "
                                    + msg.getRequestHeader().getURI().toString()
                                    + "\n The target may have replied with a poorly formed redirect due to our input.");
                return;
            }
            // Check if the resulting content contains the executed addition
            if (msg.getResponseBody().toString().contains(addedString)) {
                // We Found IT!
                // First do logging
                log.debug(
                        "[Expression Langage Injection Found] on parameter ["
                                + paramName
                                + "]  with payload ["
                                + payload
                                + "]");

                // Now create the alert message
                this.bingo(
                        Alert.RISK_HIGH,
                        Alert.CONFIDENCE_MEDIUM,
                        msg.getRequestHeader().getURI().toString(),
                        paramName,
                        payload,
                        null,
                        addedString,
                        msg);
            }

        } catch (IOException ex) {
            // Do not try to internationalise this.. we need an error message in any event..
            // if it's in English, it's still better than not having it at all.
            log.error(
                    "Expression Language Injection vulnerability check failed for parameter ["
                            + paramName
                            + "] and payload ["
                            + payload
                            + "] due to an I/O error",
                    ex);
        }
    }
}
