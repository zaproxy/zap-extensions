/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.apache.commons.configuration.ConversionException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.timing.TimingUtils;
import org.zaproxy.zap.extension.ruleconfig.RuleConfigParam;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;

/**
 * The MongoInjection scan rule identifies MongoDB injection vulnerabilities
 *
 * @author l.casciaro
 */
public class MongoDbInjectionTimingScanRule extends AbstractAppParamPlugin
        implements CommonActiveScanRuleInfo {

    // Prefix for internationalised messages used by this rule
    private static final String MESSAGE_PREFIX = "ascanalpha.mongodb.";

    private static final String RULE_SLEEP_TIME = RuleConfigParam.RULE_COMMON_SLEEP_TIME;

    private static final int BLIND_REQUEST_LIMIT = 4;
    private static final int DEFAULT_TIME_SLEEP_SEC = 5;
    private static final double TIME_CORRELATION_ERROR_RANGE = 0.15;
    private static final double TIME_SLOPE_ERROR_RANGE = 0.30;

    private static final List<String> SLEEP_INJECTION =
            List.of(
                    // Attacking $where clause
                    // function() { var x = md5( some_input ); return this.password == x;}
                    "\"); sleep({0}); print(\"",
                    "'; sleep({0}); print(\'",
                    "0); sleep({0}); print(\"",
                    // function() { var x = this.value == some_input; return x;}
                    "'; sleep({0}); var x='",
                    "\"; sleep({0}); var x=\"",
                    "0; sleep({0})",
                    // function() { return this.value == some_input }
                    "zap' || sleep({0}) && 'zap'=='zap",
                    "zap\" || sleep({0}) && \"zap\"==\"zap",
                    "0 || sleep({0})",
                    // function() { return this.value == some_function(some_imput) }
                    "zap') || sleep({0}) && hex_md5('zap",
                    "zap\") || sleep({0}) && md5(\"zap",
                    "0)  || sleep({0})",
                    // Attacking mapReduce clause (only for old versions of mongodb)
                    "_id);}, function(inj) { sleep({0});return 1;}, { out: 'x'}); db.injection.mapReduce(function() { emit(1,1");

    private static final Logger LOGGER = LogManager.getLogger(MongoDbInjectionTimingScanRule.class);
    private static final Map<String, String> ALERT_TAGS =
            CommonAlertTag.toMap(
                    CommonAlertTag.OWASP_2021_A03_INJECTION,
                    CommonAlertTag.OWASP_2017_A01_INJECTION,
                    CommonAlertTag.WSTG_V42_INPV_05_SQLI,
                    CommonAlertTag.TEST_TIMING);

    private int timeSleepSeconds = DEFAULT_TIME_SLEEP_SEC;

    private int blindTargetCount = SLEEP_INJECTION.size();

    @Override
    public int getCweId() {
        return 943;
    }

    @Override
    public int getWascId() {
        return 19;
    }

    @Override
    public int getId() {
        return 90039;
    }

    @Override
    public boolean targets(TechSet technologies) {
        return technologies.includes(Tech.MongoDB);
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name.timebased");
    }

    @Override
    public int getRisk() {
        return Alert.RISK_HIGH;
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
    public void init() {
        LOGGER.debug("Initialising MongoDB penetration tests");

        switch (getAttackStrength()) {
            case LOW:
                blindTargetCount = 6;
                break;

            default:
            case MEDIUM:
                blindTargetCount = 10;
                break;

            case HIGH:
                blindTargetCount = 12;
                break;

            case INSANE:
                blindTargetCount = SLEEP_INJECTION.size();
                break;
        }

        try {
            timeSleepSeconds = this.getConfig().getInt(RULE_SLEEP_TIME, DEFAULT_TIME_SLEEP_SEC);
        } catch (ConversionException e) {
            LOGGER.debug(
                    "Invalid value for '{}': {}",
                    RULE_SLEEP_TIME,
                    this.getConfig().getString(RULE_SLEEP_TIME));
        }
    }

    @Override
    public void scan(HttpMessage msg, String param, String value) {
        LOGGER.debug(
                "Scanning URL [{}] [{}] on param: [{}] with value: [{}] for MongoDB Injection",
                msg.getRequestHeader().getMethod(),
                msg.getRequestHeader().getURI(),
                param,
                value);

        // injection attack to $Where and $mapReduce clauses
        // The $where clause executes associated JS function one time for each tuple --> sleep time
        // = interval * nTuples
        LOGGER.debug("Starting with the javascript code injection payloads:");

        Iterator<String> it = SLEEP_INJECTION.iterator();
        for (int i = 0; !isStop() && it.hasNext() && i < blindTargetCount; i++) {
            String sleepPayload = it.next();
            AtomicReference<HttpMessage> message = new AtomicReference<>();
            String paramValue = sleepPayload.replace("{0}", String.valueOf(timeSleepSeconds));
            LOGGER.debug("Trying with the value: {}", sleepPayload);

            TimingUtils.RequestSender requestSender =
                    x -> {
                        HttpMessage timedMsg = getNewMsg();
                        message.set(timedMsg);
                        String finalPayload =
                                value + sleepPayload.replace("{0}", String.valueOf(x));
                        setParameter(timedMsg, param, finalPayload);
                        LOGGER.debug("Testing [{}] = [{}]", param, finalPayload);

                        // send the request and retrieve the response
                        sendAndReceive(timedMsg, false);
                        return TimeUnit.MILLISECONDS.toSeconds(timedMsg.getTimeElapsedMillis());
                    };

            try {
                // use TimingUtils to detect a response to sleep payloads
                boolean isInjectable =
                        TimingUtils.checkTimingDependence(
                                BLIND_REQUEST_LIMIT,
                                timeSleepSeconds,
                                requestSender,
                                TIME_CORRELATION_ERROR_RANGE,
                                TIME_SLOPE_ERROR_RANGE);

                if (isInjectable) {
                    // We Found IT!
                    LOGGER.debug(
                            "[NOSQL Injection Found] on parameter [{}] with value [{}]",
                            param,
                            paramValue);

                    // just attach this alert to the last sent message
                    buildAlert(param, paramValue, message.get()).raise();
                    break;
                }
            } catch (SocketException ex) {
                LOGGER.debug(
                        "Caught {} {} when accessing: {}.\n The target may have replied with a poorly formed redirect due to our input.",
                        ex.getClass().getName(),
                        ex.getMessage(),
                        message.get().getRequestHeader().getURI());
            } catch (IOException ex) {
                LOGGER.warn(
                        "Mongo DB Injection vulnerability check failed for parameter [{}] and payload [{}] due to an I/O error",
                        param,
                        paramValue,
                        ex);
            }
        }
    }

    private AlertBuilder buildAlert(String param, String attack, HttpMessage msg) {
        return newAlert()
                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                .setParam(param)
                .setAttack(attack)
                .setMessage(msg)
                .setOtherInfo(Constant.messages.getString(MESSAGE_PREFIX + "extrainfo.sleep"));
    }

    @Override
    public List<Alert> getExampleAlerts() {
        return List.of(buildAlert("qry", "a&sleep 5&", null).build());
    }
}
