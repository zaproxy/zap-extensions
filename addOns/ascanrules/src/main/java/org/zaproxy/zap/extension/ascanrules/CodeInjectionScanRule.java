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
import java.text.MessageFormat;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;

/**
 * Active scan rule for Code Injection testing and verification.
 * https://owasp.org/www-community/attacks/Code_Injection
 *
 * @author yhawke (2013)
 */
public class CodeInjectionScanRule extends AbstractAppParamPlugin
        implements CommonActiveScanRuleInfo {

    /** Prefix for internationalised messages used by this rule */
    private static final String MESSAGE_PREFIX = "ascanrules.codeinjection.";

    private static final Map<String, String> ALERT_TAGS;

    static {
        Map<String, String> alertTags =
                new HashMap<>(
                        CommonAlertTag.toMap(
                                CommonAlertTag.OWASP_2021_A03_INJECTION,
                                CommonAlertTag.OWASP_2017_A01_INJECTION,
                                CommonAlertTag.WSTG_V42_INPV_11_CODE_INJ));
        alertTags.put(PolicyTag.API.getTag(), "");
        alertTags.put(PolicyTag.DEV_FULL.getTag(), "");
        alertTags.put(PolicyTag.QA_STD.getTag(), "");
        alertTags.put(PolicyTag.QA_FULL.getTag(), "");
        alertTags.put(PolicyTag.SEQUENCE.getTag(), "");
        ALERT_TAGS = Collections.unmodifiableMap(alertTags);
    }

    // PHP control Token used to verify the vulnerability
    private static final String PHP_CONTROL_TOKEN = "zap_token";
    private static final String PHP_ENCODED_TOKEN =
            "chr(122).chr(97).chr(112).chr(95).chr(116).chr(111).chr(107).chr(101).chr(110)";

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
        "\"+response.write({0}*{1})+\"", "'+response.write({0}*{1})+'", "response.write({0}*{1})"
    };

    // Logger instance
    private static final Logger LOGGER = LogManager.getLogger(CodeInjectionScanRule.class);

    private static final Random RAND = new Random();
    private static final int MAX_VALUE = 999998;

    @Override
    public int getId() {
        return 90019;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    @Override
    public boolean targets(TechSet technologies) {
        return technologies.includes(Tech.ASP) || technologies.includes(Tech.PHP);
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(MESSAGE_PREFIX + "desc");
    }

    @Override
    public int getCategory() {
        return Category.INJECTION;
    }

    @Override
    public String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    @Override
    public String getReference() {
        return Constant.messages.getString(MESSAGE_PREFIX + "refs");
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    @Override
    public int getCweId() {
        return 94;
    }

    @Override
    public int getWascId() {
        return 20; // WASC-20: Improper Input Handling
    }

    @Override
    public int getRisk() {
        return Alert.RISK_HIGH;
    }

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

        // Begin scan rule execution
        LOGGER.debug(
                "Checking [{}][{}], parameter [{}] for Dynamic Code Injection Vulnerabilities",
                msg.getRequestHeader().getMethod(),
                msg.getRequestHeader().getURI(),
                paramName);

        if (inScope(Tech.PHP) && testPhpInjection(paramName)) {
            return;
        }

        if (isStop()) {
            return;
        }

        if (inScope(Tech.ASP)) {
            testAspInjection(paramName);
        }
    }

    /**
     * Tests for injection vulnerabilities in PHP code.
     *
     * @param paramName the name of the parameter will be used for testing for injection
     * @return {@code true} if the vulnerability was found, {@code false} otherwise.
     * @see #PHP_PAYLOADS
     */
    private boolean testPhpInjection(String paramName) {
        for (String phpPayload : PHP_PAYLOADS) {
            if (isStop()) {
                break;
            }

            HttpMessage msg = getNewMsg();
            setParameter(msg, paramName, phpPayload);

            LOGGER.debug("Testing [{}] = [{}]", paramName, phpPayload);

            // Send the request and retrieve the response
            try {
                sendAndReceive(msg, false);
            } catch (IOException ex) {
                LOGGER.debug(
                        "Caught {}{} when accessing: {}",
                        ex.getClass().getName(),
                        ex.getMessage(),
                        msg.getRequestHeader().getURI());
                continue; // Advance in the PHP payload loop, no point continuing on this payload
            }

            // Check if the injected content has been evaluated and printed
            if (msg.getResponseBody().toString().contains(PHP_CONTROL_TOKEN)) {
                // We Found IT!
                LOGGER.debug(
                        "[PHP Code Injection Found] on parameter [{}] with payload [{}]",
                        paramName,
                        phpPayload);

                createPhpAlert(paramName, phpPayload).setMessage(msg).raise();

                // All done. No need to look for vulnerabilities on subsequent
                // parameters on the same request (to reduce performance impact)
                return true;
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
        int bignum1 = getRandomValue();
        int bignum2 = getRandomValue();

        for (String aspPayload : ASP_PAYLOADS) {
            if (isStop()) {
                break;
            }

            HttpMessage msg = getNewMsg();
            setParameter(msg, paramName, MessageFormat.format(aspPayload, bignum1, bignum2));

            LOGGER.debug("Testing [{}] = [{}]", paramName, aspPayload);

            // Send the request and retrieve the response
            try {
                sendAndReceive(msg, false);
            } catch (IOException ex) {
                LOGGER.debug(
                        "Caught {} {} when accessing: {}",
                        ex.getClass().getName(),
                        ex.getMessage(),
                        msg.getRequestHeader().getURI());
                continue; // Advance in the ASP payload loop, no point continuing on this payload
            }

            // Check if the injected content has been evaluated and printed
            String evidence = String.valueOf((long) bignum1 * bignum2);
            if (msg.getResponseBody().toString().contains(evidence)) {
                // We Found IT!
                LOGGER.debug(
                        "[ASP Code Injection Found] on parameter [{}] with payload [{}]",
                        paramName,
                        aspPayload);

                createAspAlert(paramName, aspPayload, evidence).setMessage(msg).raise();
                return true;
            }
        }

        return false;
    }

    private static int getRandomValue() {
        return RAND.nextInt(MAX_VALUE) + 1;
    }

    private AlertBuilder createPhpAlert(String param, String attack) {
        return newAlert()
                .setName(Constant.messages.getString(MESSAGE_PREFIX + "name.php"))
                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                .setParam(param)
                .setAttack(attack)
                .setEvidence(PHP_CONTROL_TOKEN)
                .setAlertRef(getId() + "-1");
    }

    private AlertBuilder createAspAlert(String param, String attack, String evidence) {
        return newAlert()
                .setName(Constant.messages.getString(MESSAGE_PREFIX + "name.asp"))
                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                .setParam(param)
                .setAttack(attack)
                .setEvidence(evidence)
                .setAlertRef(getId() + "-2");
    }

    @Override
    public List<Alert> getExampleAlerts() {
        Alert phpAlert = createPhpAlert("param", PHP_PAYLOADS[0]).build();
        String aspPayload = MessageFormat.format(ASP_PAYLOADS[0], 268327, 513977);
        Alert aspAlert = createAspAlert("param", aspPayload, String.valueOf(137913906479L)).build();
        return List.of(phpAlert, aspAlert);
    }
}
