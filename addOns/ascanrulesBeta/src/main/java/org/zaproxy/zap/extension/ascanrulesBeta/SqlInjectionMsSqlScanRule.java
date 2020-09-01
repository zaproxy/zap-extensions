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
package org.zaproxy.zap.extension.ascanrulesBeta;

import java.io.IOException;
import java.util.concurrent.TimeUnit;
import org.apache.commons.configuration.ConversionException;
import org.apache.commons.httpclient.InvalidRedirectLocationException;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
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
public class SqlInjectionMsSqlScanRule extends AbstractAppParamPlugin {

    /** MSSQL one-line comment */
    private static final String SQL_ONE_LINE_COMMENT = " -- ";

    private static final String ORIG_VALUE_TOKEN = "<<<<ORIGINALVALUE>>>>";
    private static final String SLEEP_TOKEN = "<<<<SLEEP>>>>";

    /**
     * MsSQL specific time based injection strings. Note: <<<<ORIGINALVALUE>>>> is replaced with the
     * original parameter value at runtime in these examples below (see * comment) TODO: Add
     * SQL_MSSQL_TIME_REPLACEMENTS queries related to PARAM in SELECT/UPDATE/DELETE clause
     */
    private static final String[] SQL_MSSQL_TIME_REPLACEMENTS = {
        // Param in WHERE clause
        ORIG_VALUE_TOKEN + " WAITFOR DELAY '" + SLEEP_TOKEN + "'" + SQL_ONE_LINE_COMMENT,
        ORIG_VALUE_TOKEN + "' WAITFOR DELAY '" + SLEEP_TOKEN + "'" + SQL_ONE_LINE_COMMENT,
        ORIG_VALUE_TOKEN + "\" WAITFOR DELAY '" + SLEEP_TOKEN + "'" + SQL_ONE_LINE_COMMENT,
        ORIG_VALUE_TOKEN + ") WAITFOR DELAY '" + SLEEP_TOKEN + "'" + SQL_ONE_LINE_COMMENT,
        ORIG_VALUE_TOKEN + ") ' WAITFOR DELAY '" + SLEEP_TOKEN + "'" + SQL_ONE_LINE_COMMENT,
        ORIG_VALUE_TOKEN + ") \" WAITFOR DELAY '" + SLEEP_TOKEN + "'" + SQL_ONE_LINE_COMMENT,
        ORIG_VALUE_TOKEN + ")) WAITFOR DELAY '" + SLEEP_TOKEN + "'" + SQL_ONE_LINE_COMMENT,
        ORIG_VALUE_TOKEN + ")) ' WAITFOR DELAY '" + SLEEP_TOKEN + "'" + SQL_ONE_LINE_COMMENT,
        ORIG_VALUE_TOKEN + ")) \" WAITFOR DELAY '" + SLEEP_TOKEN + "'" + SQL_ONE_LINE_COMMENT,
        ORIG_VALUE_TOKEN + ") WAITFOR DELAY '" + SLEEP_TOKEN + "' (",
        ORIG_VALUE_TOKEN + ") ' WAITFOR DELAY '" + SLEEP_TOKEN + "' (",
        ORIG_VALUE_TOKEN + ") \" WAITFOR DELAY '" + SLEEP_TOKEN + "' (",
        ORIG_VALUE_TOKEN + ")) WAITFOR DELAY '" + SLEEP_TOKEN + "' ((",
        ORIG_VALUE_TOKEN + ")) ' WAITFOR DELAY '" + SLEEP_TOKEN + "' ((",
        ORIG_VALUE_TOKEN + ")) \" WAITFOR DELAY '" + SLEEP_TOKEN + "' ((",
    };

    /** for logging. */
    private static final Logger log = Logger.getLogger(SqlInjectionMsSqlScanRule.class);

    private static final int DEFAULT_SLEEP_TIME = 15;

    private boolean doTimeBased;
    private int doTimeMaxRequests;
    private int sleepInSeconds = DEFAULT_SLEEP_TIME;
    // how many requests have we made?
    private int countTimeBasedRequests;

    @Override
    public int getId() {
        return 40027;
    }

    @Override
    public String getName() {
        return Constant.messages.getString("ascanbeta.sqlinjection.mssql.name");
    }

    @Override
    public boolean targets(TechSet technologies) {
        return technologies.includes(Tech.MsSQL);
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("ascanbeta.sqlinjection.mssql.desc");
    }

    @Override
    public int getCategory() {
        return Category.INJECTION;
    }

    @Override
    public String getSolution() {
        return Constant.messages.getString("ascanbeta.sqlinjection.mssql.soln");
    }

    @Override
    public String getReference() {
        return Constant.messages.getString("ascanbeta.sqlinjection.mssql.refs");
    }

    @Override
    public void init() {
        if (log.isDebugEnabled()) {
            log.debug("Initialising");
        }

        // set up what we are allowed to do, depending on the attack strength that was set.
        if (this.getAttackStrength() == AttackStrength.LOW) {
            doTimeBased = true;
            doTimeMaxRequests = 3;
        } else if (this.getAttackStrength() == AttackStrength.MEDIUM) {
            doTimeBased = true;
            doTimeMaxRequests = 6;
        } else if (this.getAttackStrength() == AttackStrength.HIGH) {
            doTimeBased = true;
            doTimeMaxRequests = 12;
        } else if (this.getAttackStrength() == AttackStrength.INSANE) {
            doTimeBased = true;
            doTimeMaxRequests = 100;
        }

        // Read the sleep value from the configs
        try {
            this.sleepInSeconds =
                    this.getConfig()
                            .getInt(RuleConfigParam.RULE_COMMON_SLEEP_TIME, DEFAULT_SLEEP_TIME);
        } catch (ConversionException e) {
            log.debug(
                    "Invalid value for 'rules.common.sleep': "
                            + this.getConfig().getString(RuleConfigParam.RULE_COMMON_SLEEP_TIME));
        }
        if (log.isDebugEnabled()) {
            log.debug("Sleep set to " + sleepInSeconds + " seconds");
        }
    }

    /** scans for SQL Injection vulnerabilities, using MsSQL specific syntax. */
    @Override
    public void scan(HttpMessage originalMessage, String paramName, String paramValue) {
        try {
            // Timing Baseline check: we need to get the time that it took the original query, to
            // know if the time based check is working correctly..
            HttpMessage msgTimeBaseline = getNewMsg();
            long originalTimeUsed = getRoundTripTime(msgTimeBaseline);
            // if the time was very slow (because JSP was being compiled on first call, for
            // instance)
            // then the rest of the time based logic will fail.  Lets double-check for that scenario
            // by requesting the url again.
            // If it comes back in a more reasonable time, we will use that time instead as our
            // baseline.  If it come out in a slow fashion again,
            // we will abort the check on this URL, since we will only spend lots of time trying
            // request, when we will (very likely) not get positive results.
            int sleepTimeInMilliSeconds = sleepInSeconds * 1000;
            if (originalTimeUsed > sleepTimeInMilliSeconds) {
                long originalTimeUsed2 = getRoundTripTime(msgTimeBaseline);
                if (originalTimeUsed2 > sleepTimeInMilliSeconds) {
                    // no better the second time around.  we need to bale out.
                    if (log.isDebugEnabled()) {
                        log.debug(
                                "Both base time checks 1 and 2 for ["
                                        + msgTimeBaseline.getRequestHeader().getMethod()
                                        + "] URL ["
                                        + msgTimeBaseline.getRequestHeader().getURI()
                                        + "] are way too slow to be usable for the purposes of checking for time based SQL Injection checking.  We are aborting the check on this particular url.");
                    }
                    return;
                }
                // the second time came in within the limits. use the later timing details as the
                // base time for the checks.
                originalTimeUsed = originalTimeUsed2;
            }

            if (log.isDebugEnabled()) {
                log.debug(
                        "Scanning URL ["
                                + getBaseMsg().getRequestHeader().getMethod()
                                + "] ["
                                + getBaseMsg().getRequestHeader().getURI()
                                + "], field ["
                                + paramName
                                + "] with value ["
                                + paramValue
                                + "] for MsSQL Injection");
            }

            // Check for time based SQL Injection, using MsSQL specific syntax
            String sleepToken = getSleepToken(sleepInSeconds);
            for (int timeBasedSQLindex = 0;
                    timeBasedSQLindex < SQL_MSSQL_TIME_REPLACEMENTS.length
                            && doTimeBased
                            && countTimeBasedRequests < doTimeMaxRequests;
                    timeBasedSQLindex++) {
                HttpMessage msgAttack = getNewMsg();
                String newTimeBasedInjectionValue =
                        SQL_MSSQL_TIME_REPLACEMENTS[timeBasedSQLindex]
                                .replace(ORIG_VALUE_TOKEN, paramValue)
                                .replace(SLEEP_TOKEN, sleepToken);

                setParameter(msgAttack, paramName, newTimeBasedInjectionValue);
                long modifiedTimeUsed = getRoundTripTime(msgAttack);
                if (log.isDebugEnabled()) {
                    log.debug(
                            "Time Based SQL Injection test: ["
                                    + newTimeBasedInjectionValue
                                    + "] on field: ["
                                    + paramName
                                    + "] with value ["
                                    + newTimeBasedInjectionValue
                                    + "] took "
                                    + modifiedTimeUsed
                                    + "ms, where the original took "
                                    + originalTimeUsed
                                    + "ms");
                }
                // add some small leeway on the time, since adding a 5 (by default) second delay in
                // the SQL query will not cause the request
                // to take a full 15 (by default) seconds longer to run than the original..
                if (modifiedTimeUsed >= (originalTimeUsed + sleepInSeconds * 1000 - 200)) {
                    // takes more than 5(by default) extra seconds => likely time based SQL
                    // injection.

                    // But first double check
                    HttpMessage msgc = getNewMsg();
                    try {
                        sendAndReceive(msgc, false); // do not follow redirects
                    } catch (Exception e) {
                        // Ignore all exceptions
                    }
                    long checkTimeUsed = msgc.getTimeElapsedMillis();
                    if (checkTimeUsed >= (originalTimeUsed + (this.sleepInSeconds * 1000) - 200)) {
                        // Looks like the server is overloaded, very unlikely this is a real issue
                        continue;
                    }

                    String extraInfo =
                            Constant.messages.getString(
                                    "ascanbeta.sqlinjection.mssql.alert.timebased.extrainfo",
                                    newTimeBasedInjectionValue,
                                    modifiedTimeUsed,
                                    paramValue,
                                    originalTimeUsed);

                    newAlert()
                            .setConfidence(Alert.CONFIDENCE_MEDIUM)
                            .setUri(getBaseMsg().getRequestHeader().getURI().toString())
                            .setParam(paramName)
                            .setAttack(newTimeBasedInjectionValue)
                            .setOtherInfo(extraInfo)
                            .setMessage(msgAttack)
                            .raise();

                    if (log.isDebugEnabled()) {
                        log.debug(
                                "A likely Time Based SQL Injection Vulnerability has been found with ["
                                        + msgAttack.getRequestHeader().getMethod()
                                        + "] URL ["
                                        + msgAttack.getRequestHeader().getURI()
                                        + "] on field: ["
                                        + paramName
                                        + "]");
                    }
                    return;
                } // query took longer than the amount of time we attempted to delay it by
                // bale out if we were asked nicely
                if (isStop()) {
                    log.debug("Stopping the scan due to a user request");
                    return;
                }
            }
            // end of check for time based SQL Injection
        } catch (InvalidRedirectLocationException e) {
            if (log.isDebugEnabled()) {
                log.debug("Probably, we hit the redirection location");
            }
        } catch (Exception e) {
            log.error("An error occurred checking a url for MsSQL Injection vulnerabilities", e);
        }
    }

    private long getRoundTripTime(HttpMessage msg) throws IOException {
        try {
            sendAndReceive(msg, false); // do not follow redirects
        } catch (java.net.SocketTimeoutException e) {
            // to be expected occasionally, if the base query was one that contains some parameters
            // exploiting time based SQL injection?
            if (log.isDebugEnabled()) {
                log.debug(
                        "The Base Time Check timed out on ["
                                + msg.getRequestHeader().getMethod()
                                + "] URL ["
                                + msg.getRequestHeader().getURI()
                                + "]");
            }
        }
        countTimeBasedRequests++;
        return msg.getTimeElapsedMillis();
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
}
