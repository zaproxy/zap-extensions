/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2012 The ZAP Development Team
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
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.addon.commonlib.timing.TimingUtils;
import org.zaproxy.zap.extension.ruleconfig.RuleConfigParam;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;

/**
 * TODO: maybe implement a more specific UNION based check for Oracle (with table names)
 *
 * <p>This scan rule identifies Oracle specific SQL Injection vulnerabilities using Oracle specific
 * syntax. If it doesn't use Oracle specific syntax, it belongs in the generic SQLInjection class!
 * Note the ordering of checks, for efficiency is : 1) Error based (N/A) 2) Boolean Based (N/A -
 * uses standard syntax) 3) UNION based (TODO) 4) Stacked (N/A - uses standard syntax) 5) Blind/Time
 * Based (Yes)
 *
 * <p>See the following for some great specific tricks which could be integrated here
 * http://www.websec.ca/kb/sql_injection
 * http://pentestmonkey.net/cheat-sheet/sql-injection/oracle-sql-injection-cheat-sheet
 *
 * <p>Important Notes for the Oracle database (and useful in the code): - takes -- style comments -
 * requires a table name in normal select statements (like Hypersonic: cannot just say "select 1" or
 * "select 2" like in most RDBMSs - requires a table name in "union select" statements (like
 * Hypersonic). - does NOT allow stacked queries via JDBC driver or in PHP. - Constants in select
 * must be in single quotes, not doubles (like Hypersonic). - supports UDFs (very interesting!!) -
 * metadata select statement: TODO
 *
 * @author 70pointer
 */
public class SqlInjectionOracleTimingScanRule extends AbstractAppParamPlugin
        implements CommonActiveScanRuleInfo {

    private int sleepInSeconds;

    private int doTimeMaxRequests = 0;

    private static final String ORIG_VALUE_TOKEN = "<<<<ORIGINALVALUE>>>>";
    private static final String SLEEP_TOKEN = "<<<<SLEEP>>>>";
    private static final int DEFAULT_TIME_SLEEP_SEC = 5;
    private static final int BLIND_REQUEST_LIMIT = 4;
    // Error range allowable for statistical time-based blind attacks (0-1.0)
    private static final double TIME_CORRELATION_ERROR_RANGE = 0.15;
    private static final double TIME_SLOPE_ERROR_RANGE = 0.30;

    private static String SLEEP_FUNCTION = "DBMS_SESSION.SLEEP(" + SLEEP_TOKEN + ")";

    public static final String ONE_LINE_COMMENT = " -- ";

    private static String[] PAYLOADS = {
        "(" + SLEEP_FUNCTION + ")",
        ORIG_VALUE_TOKEN + " / (" + SLEEP_FUNCTION + ") ",
        ORIG_VALUE_TOKEN + "' / (" + SLEEP_FUNCTION + ") / '",
        ORIG_VALUE_TOKEN + "\" / (" + SLEEP_FUNCTION + ") / \"",
        ORIG_VALUE_TOKEN
                + " and exists ("
                + SLEEP_FUNCTION
                + ")"
                + ONE_LINE_COMMENT, // Param in WHERE clause somewhere
        ORIG_VALUE_TOKEN
                + "' and exists ("
                + SLEEP_FUNCTION
                + ")"
                + ONE_LINE_COMMENT, // Param in WHERE clause somewhere
        ORIG_VALUE_TOKEN
                + "\" and exists ("
                + SLEEP_FUNCTION
                + ")"
                + ONE_LINE_COMMENT, // Param in WHERE clause somewhere
        ORIG_VALUE_TOKEN
                + ") and exists ("
                + SLEEP_FUNCTION
                + ")"
                + ONE_LINE_COMMENT, // Param in WHERE clause somewhere
        ORIG_VALUE_TOKEN
                + " or exists ("
                + SLEEP_FUNCTION
                + ")"
                + ONE_LINE_COMMENT, // Param in WHERE clause somewhere
        ORIG_VALUE_TOKEN
                + "' or exists ("
                + SLEEP_FUNCTION
                + ")"
                + ONE_LINE_COMMENT, // Param in WHERE clause somewhere
        ORIG_VALUE_TOKEN
                + "\" or exists ("
                + SLEEP_FUNCTION
                + ")"
                + ONE_LINE_COMMENT, // Param in WHERE clause somewhere
        ORIG_VALUE_TOKEN
                + ") or exists ("
                + SLEEP_FUNCTION
                + ")"
                + ONE_LINE_COMMENT, // Param in WHERE clause somewhere
    };

    private static final Map<String, String> ALERT_TAGS;

    static {
        Map<String, String> alertTags =
                new HashMap<>(
                        CommonAlertTag.toMap(
                                CommonAlertTag.OWASP_2021_A03_INJECTION,
                                CommonAlertTag.OWASP_2017_A01_INJECTION,
                                CommonAlertTag.WSTG_V42_INPV_05_SQLI,
                                CommonAlertTag.HIPAA,
                                CommonAlertTag.PCI_DSS,
                                CommonAlertTag.TEST_TIMING));
        alertTags.put(PolicyTag.DEV_FULL.getTag(), "");
        alertTags.put(PolicyTag.QA_STD.getTag(), "");
        alertTags.put(PolicyTag.QA_FULL.getTag(), "");
        alertTags.put(PolicyTag.SEQUENCE.getTag(), "");
        alertTags.put(PolicyTag.PENTEST.getTag(), "");
        ALERT_TAGS = Collections.unmodifiableMap(alertTags);
    }

    private static final Logger LOGGER =
            LogManager.getLogger(SqlInjectionOracleTimingScanRule.class);

    @Override
    public int getId() {
        return 40021;
    }

    @Override
    public String getName() {
        return Constant.messages.getString("ascanrules.sqlinjection.oracle.name");
    }

    @Override
    public boolean targets(TechSet technologies) {
        return technologies.includes(Tech.Oracle);
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("ascanrules.sqlinjection.desc");
    }

    @Override
    public int getCategory() {
        return Category.INJECTION;
    }

    @Override
    public String getSolution() {
        return Constant.messages.getString("ascanrules.sqlinjection.soln");
    }

    @Override
    public String getReference() {
        return Constant.messages.getString("ascanrules.sqlinjection.refs");
    }

    @Override
    public void init() {
        LOGGER.debug("Initialising");

        if (this.getAttackStrength() == AttackStrength.LOW) {
            doTimeMaxRequests = 3;
        } else if (this.getAttackStrength() == AttackStrength.MEDIUM) {
            doTimeMaxRequests = 5;
        } else if (this.getAttackStrength() == AttackStrength.HIGH) {
            doTimeMaxRequests = 10;
        } else if (this.getAttackStrength() == AttackStrength.INSANE) {
            doTimeMaxRequests = 100;
        }

        // Read the sleep value from the configs
        try {
            sleepInSeconds =
                    this.getConfig()
                            .getInt(RuleConfigParam.RULE_COMMON_SLEEP_TIME, DEFAULT_TIME_SLEEP_SEC);
        } catch (ConversionException e) {
            LOGGER.debug(
                    "Invalid value for 'rules.common.sleep': {}",
                    this.getConfig().getString(RuleConfigParam.RULE_COMMON_SLEEP_TIME));
        }
        LOGGER.debug("Sleep set to {} seconds", sleepInSeconds);
    }

    @Override
    public void scan(HttpMessage originalMessage, String paramName, String paramValue) {
        for (int payloadIndex = 0, countTimeBasedRequests = 0;
                payloadIndex < PAYLOADS.length && countTimeBasedRequests < doTimeMaxRequests;
                payloadIndex++, countTimeBasedRequests++) {
            if (isStop()) {
                LOGGER.debug("Stopping the scan due to a user request.");
                return;
            }
            AtomicReference<HttpMessage> message = new AtomicReference<>();
            String payloadValue = PAYLOADS[payloadIndex].replace(ORIG_VALUE_TOKEN, paramValue);
            TimingUtils.RequestSender requestSender =
                    x -> {
                        HttpMessage timedMsg = getNewMsg();
                        message.compareAndSet(null, timedMsg);
                        String finalPayload =
                                payloadValue.replace(SLEEP_TOKEN, String.valueOf((int) x));
                        setParameter(timedMsg, paramName, finalPayload);
                        sendAndReceive(timedMsg, false); // do not follow redirects
                        return TimeUnit.MILLISECONDS.toSeconds(timedMsg.getTimeElapsedMillis());
                    };
            boolean isInjectable;
            try {
                // Use TimingUtils to detect a response to sleep payloads
                isInjectable =
                        TimingUtils.checkTimingDependence(
                                BLIND_REQUEST_LIMIT,
                                sleepInSeconds,
                                requestSender,
                                TIME_CORRELATION_ERROR_RANGE,
                                TIME_SLOPE_ERROR_RANGE);
            } catch (IOException ex) {
                LOGGER.debug(
                        "Caught {} {} when accessing: {}.",
                        ex.getClass().getName(),
                        ex.getMessage(),
                        message.get().getRequestHeader().getURI());
                continue; // Something went wrong, move to next blind iteration
            }

            if (isInjectable) {
                String finalPayloadValue =
                        payloadValue.replace(SLEEP_TOKEN, String.valueOf(sleepInSeconds));
                LOGGER.debug(
                        "Time Based Oracle SQL Injection - Found on parameter [{}] with value [{}]",
                        paramName,
                        paramValue);

                newAlert()
                        .setConfidence(Alert.CONFIDENCE_MEDIUM)
                        .setUri(getBaseMsg().getRequestHeader().getURI().toString())
                        .setParam(paramName)
                        .setAttack(finalPayloadValue)
                        .setMessage(message.get())
                        .setOtherInfo(
                                Constant.messages.getString(
                                        "ascanrules.sqlinjection.alert.timebased.extrainfo",
                                        finalPayloadValue,
                                        message.get().getTimeElapsedMillis(),
                                        paramValue,
                                        getBaseMsg().getTimeElapsedMillis()))
                        .raise();
                return;
            }
        }
    }

    public void setSleepInSeconds(int sleep) {
        this.sleepInSeconds = sleep;
    }

    @Override
    public int getRisk() {
        return Alert.RISK_HIGH;
    }

    @Override
    public int getCweId() {
        return 89;
    }

    @Override
    public int getWascId() {
        return 19;
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }
}
