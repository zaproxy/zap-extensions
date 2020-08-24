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
package org.zaproxy.zap.extension.ascanrulesBeta;

import java.net.SocketException;
import java.util.LinkedHashMap;
import java.util.Map;
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
 * The SqlInjectionMyqlScanRule identifies MySQL specific SQL Injection vulnerabilities using MySQL
 * specific syntax. If it doesn't use MySQL specific syntax, it belongs in the generic SQLInjection
 * class! Note the ordering of checks, for efficiency is : 1) Error based (N/A) 2) Boolean Based
 * (N/A - uses standard syntax) 3) UNION based (N/A - uses standard syntax) 4) Stacked (N/A - uses
 * standard syntax) 5) Blind/Time Based (Yes - uses specific syntax)
 *
 * <p>See the following for some great MySQL specific tricks which could be integrated here
 * http://www.websec.ca/kb/sql_injection#MySQL_Stacked_Queries
 * http://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet
 *
 * @author 70pointer
 */
public class SqlInjectionMyqlScanRule extends AbstractAppParamPlugin {

    private boolean doTimeBased = false;

    private int doTimeMaxRequests = 0;

    private int sleep = 5;

    /** MySQL one-line comment */
    public static final String SQL_ONE_LINE_COMMENT = " -- ";

    private static final String ORIG_VALUE_TOKEN = "<<<<ORIGINALVALUE>>>>";
    private static final String SLEEP_TOKEN = "<<<<SLEEP>>>>";

    /**
     * create a map of SQL related error message fragments, and map them back to the RDBMS that they
     * are associated with keep the ordering the same as the order in which the values are inserted,
     * to allow the more (subjectively judged) common cases to be tested first Note: these should
     * represent actual (driver level) error messages for things like syntax error, otherwise we are
     * simply guessing that the string should/might occur.
     */
    private static final Map<String, String> SQL_ERROR_TO_DBMS = new LinkedHashMap<>();

    static {
        SQL_ERROR_TO_DBMS.put("com.mysql.jdbc.exceptions", "MySQL");
        SQL_ERROR_TO_DBMS.put("org.gjt.mm.mysql", "MySQL");
        // Note: only MYSQL mappings here.
    }

    /** MySQL specific time based injection strings. */

    // Note: <<<<ORIGINALVALUE>>>> is replaced with the original parameter value at runtime in these
    // examples below (see * comment)
    // TODO: maybe add support for ')' after the original value, before the sleeps
    private static String[] SQL_MYSQL_TIME_REPLACEMENTS = {
        // LOW
        ORIG_VALUE_TOKEN
                + " / sleep("
                + SLEEP_TOKEN
                + ") ", // MySQL >= 5.0.12. Might work if "SET sql_mode='STRICT_TRANS_TABLES'" is
        // OFF. Try without a comment, to target use of the field in the SELECT
        // clause, but also in the WHERE clauses.
        ORIG_VALUE_TOKEN
                + "' / sleep("
                + SLEEP_TOKEN
                + ") / '", // MySQL >= 5.0.12. Might work if "SET sql_mode='STRICT_TRANS_TABLES'" is
        // OFF. Try without a comment, to target use of the field in the SELECT
        // clause, but also in the WHERE clauses.
        ORIG_VALUE_TOKEN
                + "\" / sleep("
                + SLEEP_TOKEN
                + ") / \"", // MySQL >= 5.0.12. Might work if "SET sql_mode='STRICT_TRANS_TABLES'"
        // is OFF. Try without a comment, to target use of the field in the
        // SELECT clause, but also in the WHERE clauses.
        // MEDIUM
        ORIG_VALUE_TOKEN
                + " and 0 in (select sleep("
                + SLEEP_TOKEN
                + ") )"
                + SQL_ONE_LINE_COMMENT, // MySQL >= 5.0.12. Param in WHERE clause.
        ORIG_VALUE_TOKEN
                + "' and 0 in (select sleep("
                + SLEEP_TOKEN
                + ") )"
                + SQL_ONE_LINE_COMMENT, // MySQL >= 5.0.12. Param in WHERE clause.
        ORIG_VALUE_TOKEN
                + "\" and 0 in (select sleep("
                + SLEEP_TOKEN
                + ") )"
                + SQL_ONE_LINE_COMMENT, // MySQL >= 5.0.12. Param in WHERE clause.
        // HIGH
        ORIG_VALUE_TOKEN
                + " where 0 in (select sleep("
                + SLEEP_TOKEN
                + ") )"
                + SQL_ONE_LINE_COMMENT, // MySQL >= 5.0.12. Param in SELECT/UPDATE/DELETE clause.
        ORIG_VALUE_TOKEN
                + "' where 0 in (select sleep("
                + SLEEP_TOKEN
                + ") )"
                + SQL_ONE_LINE_COMMENT, // MySQL >= 5.0.12. Param in SELECT/UPDATE/DELETE clause.
        ORIG_VALUE_TOKEN
                + "\" where 0 in (select sleep("
                + SLEEP_TOKEN
                + ") )"
                + SQL_ONE_LINE_COMMENT, // MySQL >= 5.0.12. Param in SELECT/UPDATE/DELETE clause.
        ORIG_VALUE_TOKEN
                + " or 0 in (select sleep("
                + SLEEP_TOKEN
                + ") )"
                + SQL_ONE_LINE_COMMENT, // MySQL >= 5.0.12. Param in WHERE clause.
        ORIG_VALUE_TOKEN
                + "' or 0 in (select sleep("
                + SLEEP_TOKEN
                + ") )"
                + SQL_ONE_LINE_COMMENT, // MySQL >= 5.0.12. Param in WHERE clause.
        ORIG_VALUE_TOKEN
                + "\" or 0 in (select sleep("
                + SLEEP_TOKEN
                + ") )"
                + SQL_ONE_LINE_COMMENT, // MySQL >= 5.0.12. Param in WHERE clause.
        // INSANE
        ORIG_VALUE_TOKEN
                + " where 0 in (select sleep("
                + SLEEP_TOKEN
                + ") ) ", // MySQL >= 5.0.12. Param in SELECT/UPDATE/DELETE clause.
        ORIG_VALUE_TOKEN
                + "' where 0 in (select sleep("
                + SLEEP_TOKEN
                + ") ) and ''='", // MySQL >= 5.0.12. Param in SELECT/UPDATE/DELETE clause.
        ORIG_VALUE_TOKEN
                + "\" where 0 in (select sleep("
                + SLEEP_TOKEN
                + ") ) and \"\"=\"", // MySQL >= 5.0.12. Param in SELECT/UPDATE/DELETE clause.
        ORIG_VALUE_TOKEN
                + " and 0 in (select sleep("
                + SLEEP_TOKEN
                + ") ) ", // MySQL >= 5.0.12. Param in WHERE clause.
        ORIG_VALUE_TOKEN
                + "' and 0 in (select sleep("
                + SLEEP_TOKEN
                + ") ) and ''='", // MySQL >= 5.0.12. Param in WHERE clause.
        ORIG_VALUE_TOKEN
                + "\" and 0 in (select sleep("
                + SLEEP_TOKEN
                + ") ) and \"\"=\"", // MySQL >= 5.0.12. Param in WHERE clause.
        ORIG_VALUE_TOKEN
                + " or 0 in (select sleep("
                + SLEEP_TOKEN
                + ") ) ", // MySQL >= 5.0.12. Param in WHERE clause.
        ORIG_VALUE_TOKEN
                + "' or 0 in (select sleep("
                + SLEEP_TOKEN
                + ") ) and ''='", // MySQL >= 5.0.12. Param in WHERE clause.
        ORIG_VALUE_TOKEN
                + "\" or 0 in (select sleep("
                + SLEEP_TOKEN
                + ") ) and \"\"=\"", // MySQL >= 5.0.12. Param in WHERE clause.
    };

    /** for logging. */
    private static Logger log = Logger.getLogger(SqlInjectionMyqlScanRule.class);

    /** determines if we should output Debug level logging */
    private boolean debugEnabled = log.isDebugEnabled();

    @Override
    public int getId() {
        return 40019;
    }

    @Override
    public String getName() {
        return Constant.messages.getString("ascanbeta.sqlinjection.mysql.name");
    }

    @Override
    public boolean targets(TechSet technologies) {
        return technologies.includes(Tech.MySQL);
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("ascanbeta.sqlinjection.desc");
    }

    @Override
    public int getCategory() {
        return Category.INJECTION;
    }

    @Override
    public String getSolution() {
        return Constant.messages.getString("ascanbeta.sqlinjection.soln");
    }

    @Override
    public String getReference() {
        return Constant.messages.getString("ascanbeta.sqlinjection.refs");
    }

    @Override
    public void init() {
        if (this.debugEnabled) log.debug("Initialising");

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
            this.sleep = this.getConfig().getInt(RuleConfigParam.RULE_COMMON_SLEEP_TIME, 5);
        } catch (ConversionException e) {
            log.debug(
                    "Invalid value for 'rules.common.sleep': "
                            + this.getConfig().getString(RuleConfigParam.RULE_COMMON_SLEEP_TIME));
        }
        if (this.debugEnabled) {
            log.debug("Sleep set to " + sleep + " seconds");
        }
    }

    /**
     * scans for SQL Injection vulnerabilities, using MySQL specific syntax. If it doesn't use
     * specifically MySQL syntax, it does not belong in here, but in TestSQLInjection
     */
    @Override
    public void scan(HttpMessage originalMessage, String paramName, String originalParamValue) {

        try {
            // Timing Baseline check: we need to get the time that it took the original query, to
            // know if the time based check is working correctly..
            HttpMessage msgTimeBaseline = getNewMsg();
            long originalTimeStarted = System.currentTimeMillis();
            try {
                sendAndReceive(msgTimeBaseline, false); // do not follow redirects
            } catch (java.net.SocketTimeoutException e) {
                // to be expected occasionally, if the base query was one that contains some
                // parameters exploiting time based SQL injection?
                if (this.debugEnabled)
                    log.debug(
                            "The Base Time Check timed out on ["
                                    + msgTimeBaseline.getRequestHeader().getMethod()
                                    + "] URL ["
                                    + msgTimeBaseline.getRequestHeader().getURI().getURI()
                                    + "]");
            } catch (SocketException ex) {
                if (this.debugEnabled)
                    log.debug(
                            "Caught "
                                    + ex.getClass().getName()
                                    + " "
                                    + ex.getMessage()
                                    + " when accessing: "
                                    + msgTimeBaseline.getRequestHeader().getURI().toString());
                return; // No need to keep going
            }
            long originalTimeUsed = System.currentTimeMillis() - originalTimeStarted;
            // if the time was very slow (because JSP was being compiled on first call, for
            // instance)
            // then the rest of the time based logic will fail.  Lets double-check for that scenario
            // by requesting the url again.
            // If it comes back in a more reasonable time, we will use that time instead as our
            // baseline.  If it come out in a slow fashion again,
            // we will abort the check on this URL, since we will only spend lots of time trying
            // request, when we will (very likely) not get positive results.
            if (originalTimeUsed > sleep * 1000) {
                long originalTimeStarted2 = System.currentTimeMillis();
                try {
                    sendAndReceive(msgTimeBaseline, false); // do not follow redirects
                } catch (java.net.SocketTimeoutException e) {
                    // to be expected occasionally, if the base query was one that contains some
                    // parameters exploiting time based SQL injection?
                    if (this.debugEnabled)
                        log.debug(
                                "Base Time Check 2 timed out on ["
                                        + msgTimeBaseline.getRequestHeader().getMethod()
                                        + "] URL ["
                                        + msgTimeBaseline.getRequestHeader().getURI().getURI()
                                        + "]");
                } catch (SocketException ex) {
                    if (this.debugEnabled)
                        log.debug(
                                "Caught "
                                        + ex.getClass().getName()
                                        + " "
                                        + ex.getMessage()
                                        + " when accessing: "
                                        + msgTimeBaseline.getRequestHeader().getURI().toString());
                    return; // No need to keep going
                }
                long originalTimeUsed2 = System.currentTimeMillis() - originalTimeStarted2;
                if (originalTimeUsed2 > sleep * 1000) {
                    // no better the second time around.  we need to bale out.
                    if (this.debugEnabled)
                        log.debug(
                                "Both base time checks 1 and 2 for ["
                                        + msgTimeBaseline.getRequestHeader().getMethod()
                                        + "] URL ["
                                        + msgTimeBaseline.getRequestHeader().getURI().getURI()
                                        + "] are way too slow to be usable for the purposes of checking for time based SQL Injection checking.  We are aborting the check on this particular url.");
                    return;
                } else {
                    // phew.  the second time came in within the limits. use the later timing
                    // details as the base time for the checks.
                    originalTimeUsed = originalTimeUsed2;
                    originalTimeStarted = originalTimeStarted2;
                }
            }
            // end of timing baseline check

            int countTimeBasedRequests = 0;

            if (this.debugEnabled)
                log.debug(
                        "Scanning URL ["
                                + getBaseMsg().getRequestHeader().getMethod()
                                + "] ["
                                + getBaseMsg().getRequestHeader().getURI()
                                + "], ["
                                + paramName
                                + "] with value ["
                                + originalParamValue
                                + "] for SQL Injection");

            // MySQL specific time-based SQL injection checks
            for (int timeBasedSQLindex = 0;
                    timeBasedSQLindex < SQL_MYSQL_TIME_REPLACEMENTS.length
                            && doTimeBased
                            && countTimeBasedRequests < doTimeMaxRequests;
                    timeBasedSQLindex++) {
                HttpMessage msg3 = getNewMsg();
                String newTimeBasedInjectionValue =
                        SQL_MYSQL_TIME_REPLACEMENTS[timeBasedSQLindex]
                                .replace(ORIG_VALUE_TOKEN, originalParamValue)
                                .replace(SLEEP_TOKEN, Integer.toString(sleep));
                setParameter(msg3, paramName, newTimeBasedInjectionValue);

                // send it.
                long modifiedTimeStarted = System.currentTimeMillis();
                try {
                    sendAndReceive(msg3, false); // do not follow redirects
                    countTimeBasedRequests++;
                } catch (java.net.SocketTimeoutException e) {
                    // to be expected occasionally, if the contains some parameters exploiting time
                    // based SQL injection
                    if (this.debugEnabled)
                        log.debug(
                                "The time check query timed out on ["
                                        + msg3.getRequestHeader().getMethod()
                                        + "] URL ["
                                        + msg3.getRequestHeader().getURI().getURI()
                                        + "] on field: ["
                                        + paramName
                                        + "]");
                } catch (SocketException ex) {
                    if (this.debugEnabled)
                        log.debug(
                                "Caught "
                                        + ex.getClass().getName()
                                        + " "
                                        + ex.getMessage()
                                        + " when accessing: "
                                        + msg3.getRequestHeader().getURI().toString());
                    return; // No need to keep going
                }
                long modifiedTimeUsed = System.currentTimeMillis() - modifiedTimeStarted;

                if (this.debugEnabled)
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

                // add some small leeway on the time, since adding a 5 (by default) second delay in
                // the SQL query will not cause the request
                // to take a full 5 (by default) seconds longer to run than the original..
                if (modifiedTimeUsed >= (originalTimeUsed + (sleep * 1000) - 200)) {
                    // takes more than 5 (by default) extra seconds => likely time based SQL
                    // injection. Raise it

                    // Likely a SQL Injection. Raise it
                    String extraInfo =
                            Constant.messages.getString(
                                    "ascanbeta.sqlinjection.alert.timebased.extrainfo",
                                    newTimeBasedInjectionValue,
                                    modifiedTimeUsed,
                                    originalParamValue,
                                    originalTimeUsed);

                    // raise the alert
                    newAlert()
                            .setConfidence(Alert.CONFIDENCE_MEDIUM)
                            .setUri(getBaseMsg().getRequestHeader().getURI().getURI())
                            .setParam(paramName)
                            .setAttack(newTimeBasedInjectionValue)
                            .setOtherInfo(extraInfo)
                            .setMessage(msg3)
                            .raise();

                    if (this.debugEnabled)
                        log.debug(
                                "A likely Time Based SQL Injection Vulnerability has been found with ["
                                        + msg3.getRequestHeader().getMethod()
                                        + "] URL ["
                                        + msg3.getRequestHeader().getURI().getURI()
                                        + "] on field: ["
                                        + paramName
                                        + "]");

                    return;
                } // query took longer than the amount of time we attempted to retard it by
                // bale out if we were asked nicely
                if (isStop()) {
                    if (this.debugEnabled) log.debug("Stopping the scan due to a user request");
                    return;
                }
            } // for each time based SQL index
            // end of check for MySQL time based SQL Injection

        } catch (InvalidRedirectLocationException e) {
            // Not an error, just means we probably attacked the redirect location
        } catch (Exception e) {
            // Do not try to internationalise this.. we need an error message in any event..
            // if it's in English, it's still better than not having it at all.
            log.error(
                    "An error occurred checking a url for MySQL SQL Injection vulnerabilities", e);
        }
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
