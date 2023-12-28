/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2017 The ZAP Development Team
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
 * The SqlInjectionMsSqlScanRule identifies MsSQL specific SQL Injection vulnerabilities using MsSQL
 * specific syntax. If it doesn't use MsSQL specific syntax, it belongs in the generic SQLInjection
 * class! Note the ordering of checks, for efficiency is : 1) Error based (N/A) 2) Boolean Based
 * (N/A - uses standard syntax) 3) UNION based (N/A - uses standard syntax) 4) Stacked (N/A - uses
 * standard syntax) 5) Blind/Time Based (Yes - uses specific syntax)
 *
 * <p>See the following for some great MySQL specific tricks which could be integrated here
 * http://www.websec.ca/kb/sql_injection#MSSQL_Stacked_Queries
 * http://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet
 */
public class SqlInjectionMsSqlScanRule extends AbstractAppParamPlugin
        implements CommonActiveScanRuleInfo {

    /** MSSQL one-line comment */
    private static final String SQL_ONE_LINE_COMMENT = " -- ";

    private static final String ORIG_VALUE_TOKEN = "<<<<ORIGINALVALUE>>>>";
    private static final String SLEEP_TOKEN = "<<<<SLEEP>>>>";

    /**
     * MsSQL specific time based injection strings. Note: <<<<ORIGINALVALUE>>>> is replaced with the
     * original parameter value at runtime in these examples below (see * comment) TODO: Add
     * SQL_MSSQL_TIME_REPLACEMENTS queries related to PARAM in SELECT/UPDATE/DELETE clause
     */
    private static final List<String> SQL_MSSQL_TIME_REPLACEMENTS =
            List.of(
                    // Param in WHERE clause
                    ORIG_VALUE_TOKEN
                            + " WAITFOR DELAY '"
                            + SLEEP_TOKEN
                            + "'"
                            + SQL_ONE_LINE_COMMENT,
                    ORIG_VALUE_TOKEN
                            + "' WAITFOR DELAY '"
                            + SLEEP_TOKEN
                            + "'"
                            + SQL_ONE_LINE_COMMENT,
                    ORIG_VALUE_TOKEN
                            + "\" WAITFOR DELAY '"
                            + SLEEP_TOKEN
                            + "'"
                            + SQL_ONE_LINE_COMMENT,
                    ORIG_VALUE_TOKEN
                            + ") WAITFOR DELAY '"
                            + SLEEP_TOKEN
                            + "'"
                            + SQL_ONE_LINE_COMMENT,
                    ORIG_VALUE_TOKEN
                            + ") ' WAITFOR DELAY '"
                            + SLEEP_TOKEN
                            + "'"
                            + SQL_ONE_LINE_COMMENT,
                    ORIG_VALUE_TOKEN
                            + ") \" WAITFOR DELAY '"
                            + SLEEP_TOKEN
                            + "'"
                            + SQL_ONE_LINE_COMMENT,
                    ORIG_VALUE_TOKEN
                            + ")) WAITFOR DELAY '"
                            + SLEEP_TOKEN
                            + "'"
                            + SQL_ONE_LINE_COMMENT,
                    ORIG_VALUE_TOKEN
                            + ")) ' WAITFOR DELAY '"
                            + SLEEP_TOKEN
                            + "'"
                            + SQL_ONE_LINE_COMMENT,
                    ORIG_VALUE_TOKEN
                            + ")) \" WAITFOR DELAY '"
                            + SLEEP_TOKEN
                            + "'"
                            + SQL_ONE_LINE_COMMENT,
                    ORIG_VALUE_TOKEN + ") WAITFOR DELAY '" + SLEEP_TOKEN + "' (",
                    ORIG_VALUE_TOKEN + ") ' WAITFOR DELAY '" + SLEEP_TOKEN + "' (",
                    ORIG_VALUE_TOKEN + ") \" WAITFOR DELAY '" + SLEEP_TOKEN + "' (",
                    ORIG_VALUE_TOKEN + ")) WAITFOR DELAY '" + SLEEP_TOKEN + "' ((",
                    ORIG_VALUE_TOKEN + ")) ' WAITFOR DELAY '" + SLEEP_TOKEN + "' ((",
                    ORIG_VALUE_TOKEN + ")) \" WAITFOR DELAY '" + SLEEP_TOKEN + "' ((");

    /** The default number of seconds used in time-based attacks (i.e. sleep commands). */
    private static final int DEFAULT_SLEEP_TIME = 5;

    // limit the maximum number of requests sent for time-based attack detection
    private static final int BLIND_REQUESTS_LIMIT = 4;

    // error range allowable for statistical time-based blind attacks (0-1.0)
    private static final double TIME_CORRELATION_ERROR_RANGE = 0.15;
    private static final double TIME_SLOPE_ERROR_RANGE = 0.30;

    /** for logging. */
    private static final Logger LOGGER = LogManager.getLogger(SqlInjectionMsSqlScanRule.class);

    private static final Map<String, String> ALERT_TAGS =
            CommonAlertTag.toMap(
                    CommonAlertTag.OWASP_2021_A03_INJECTION,
                    CommonAlertTag.OWASP_2017_A01_INJECTION,
                    CommonAlertTag.WSTG_V42_INPV_05_SQLI);

    /** The number of seconds used in time-based attacks (i.e. sleep commands). */
    private int timeSleepSeconds = DEFAULT_SLEEP_TIME;

    private int blindTargetCount = SQL_MSSQL_TIME_REPLACEMENTS.size();

    @Override
    public int getId() {
        return 40027;
    }

    @Override
    public String getName() {
        return Constant.messages.getString("ascanrules.sqlinjection.mssql.name");
    }

    @Override
    public boolean targets(TechSet technologies) {
        return technologies.includes(Tech.MsSQL);
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

        // set up what we are allowed to do, depending on the attack strength that was set.
        if (this.getAttackStrength() == AttackStrength.LOW) {
            blindTargetCount = 6;
        } else if (this.getAttackStrength() == AttackStrength.MEDIUM) {
            blindTargetCount = 10;
        } else if (this.getAttackStrength() == AttackStrength.HIGH) {
            blindTargetCount = 12;
        } else if (this.getAttackStrength() == AttackStrength.INSANE) {
            blindTargetCount = SQL_MSSQL_TIME_REPLACEMENTS.size();
        }

        // Read the sleep value from the configs
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

    /** scans for SQL Injection vulnerabilities, using MsSQL specific syntax. */
    @Override
    public void scan(HttpMessage originalMessage, String paramName, String paramValue) {
        LOGGER.debug(
                "Scanning URL [{}] [{}], field [{}] with value [{}] for MsSQL Injection",
                getBaseMsg().getRequestHeader().getMethod(),
                getBaseMsg().getRequestHeader().getURI(),
                paramName,
                paramValue);

        Iterator<String> it = SQL_MSSQL_TIME_REPLACEMENTS.iterator();
        for (int i = 0; !isStop() && it.hasNext() && i < blindTargetCount; i++) {
            AtomicReference<HttpMessage> message = new AtomicReference<>();
            AtomicReference<String> attack = new AtomicReference<>();
            String sleepPayload = it.next();
            TimingUtils.RequestSender requestSender =
                    x -> {
                        HttpMessage msg = getNewMsg();
                        message.compareAndSet(null, msg);

                        String finalPayload =
                                sleepPayload
                                        .replace(ORIG_VALUE_TOKEN, paramValue)
                                        .replace(SLEEP_TOKEN, getSleepToken((int) x));

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
                            "[Time Based SQL Injection Found] on parameter [{}] with value [{}]",
                            paramName,
                            attack.get());

                    String extraInfo =
                            Constant.messages.getString(
                                    "ascanrules.sqlinjection.mssql.alert.timebased.extrainfo",
                                    attack.get(),
                                    message.get().getTimeElapsedMillis(),
                                    paramValue,
                                    getBaseMsg().getTimeElapsedMillis());

                    newAlert()
                            .setConfidence(Alert.CONFIDENCE_MEDIUM)
                            .setUri(getBaseMsg().getRequestHeader().getURI().toString())
                            .setParam(paramName)
                            .setAttack(attack.get())
                            .setOtherInfo(extraInfo)
                            .setMessage(message.get())
                            .raise();
                    break;
                }
            } catch (SocketException ex) {
                LOGGER.debug(
                        "Caught {} {} when accessing: {}.\n The target may have replied with a poorly formed redirect due to our input.",
                        ex.getClass().getName(),
                        ex.getMessage(),
                        message.get().getRequestHeader().getURI());
            } catch (IOException ex) {
                LOGGER.debug(
                        "Check failed for parameter [{}] and payload [{}] due to an I/O error",
                        paramName,
                        attack.get(),
                        ex);
            }
        }
    }

    private static String getSleepToken(int totalTimeInSeconds) {
        long hoursInTotalTime = TimeUnit.SECONDS.toHours(totalTimeInSeconds);
        totalTimeInSeconds %= 3600;
        long minutesInTotalTime = TimeUnit.SECONDS.toMinutes(totalTimeInSeconds);
        totalTimeInSeconds %= 60;
        long secondsInTotalTime = totalTimeInSeconds;
        return (Long.toString(hoursInTotalTime)
                + ":"
                + Long.toString(minutesInTotalTime)
                + ":"
                + Long.toString(secondsInTotalTime));
    }

    void setSleepInSeconds(int sleep) {
        this.timeSleepSeconds = sleep;
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
