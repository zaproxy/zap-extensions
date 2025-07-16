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

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
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
 * must be in single quotes, not doubles (like Hypersonic). - supports UDFs (very interesting!!) - 5
 * second delay select statement: SELECT UTL_INADDR.get_host_name('10.0.0.1') from dual union SELECT
 * UTL_INADDR.get_host_name('10.0.0.2') from dual union SELECT UTL_INADDR.get_host_name('10.0.0.3')
 * from dual union SELECT UTL_INADDR.get_host_name('10.0.0.4') from dual union SELECT
 * UTL_INADDR.get_host_name('10.0.0.5') from dual - metadata select statement: TODO
 *
 * @author 70pointer
 */
public class SqlInjectionOracleTimingScanRule extends AbstractAppParamPlugin
        implements CommonActiveScanRuleInfo {

    private int expectedDelayInMs = 5000;

    private int doTimeMaxRequests = 0;

    /** Oracle one-line comment */
    public static final String SQL_ONE_LINE_COMMENT = " -- ";

    /** the 5 second sleep function in Oracle SQL */
    private static String SQL_ORACLE_TIME_SELECT =
            "SELECT  UTL_INADDR.get_host_name('10.0.0.1') from dual union SELECT  UTL_INADDR.get_host_name('10.0.0.2') from dual union SELECT  UTL_INADDR.get_host_name('10.0.0.3') from dual union SELECT  UTL_INADDR.get_host_name('10.0.0.4') from dual union SELECT  UTL_INADDR.get_host_name('10.0.0.5') from dual";

    /** Oracle specific time based injection strings. each for 5 seconds */

    // Note: <<<<ORIGINALVALUE>>>> is replaced with the original parameter value at runtime in these
    // examples below (see * comment)
    // TODO: maybe add support for ')' after the original value, before the sleeps
    private static String[] SQL_ORACLE_TIME_REPLACEMENTS = {
        "(" + SQL_ORACLE_TIME_SELECT + ")",
        "<<<<ORIGINALVALUE>>>> / (" + SQL_ORACLE_TIME_SELECT + ") ",
        "<<<<ORIGINALVALUE>>>>' / (" + SQL_ORACLE_TIME_SELECT + ") / '",
        "<<<<ORIGINALVALUE>>>>\" / (" + SQL_ORACLE_TIME_SELECT + ") / \"",
        "<<<<ORIGINALVALUE>>>> and exists ("
                + SQL_ORACLE_TIME_SELECT
                + ")"
                + SQL_ONE_LINE_COMMENT, // Param in WHERE clause somewhere
        "<<<<ORIGINALVALUE>>>>' and exists ("
                + SQL_ORACLE_TIME_SELECT
                + ")"
                + SQL_ONE_LINE_COMMENT, // Param in WHERE clause somewhere
        "<<<<ORIGINALVALUE>>>>\" and exists ("
                + SQL_ORACLE_TIME_SELECT
                + ")"
                + SQL_ONE_LINE_COMMENT, // Param in WHERE clause somewhere
        "<<<<ORIGINALVALUE>>>>) and exists ("
                + SQL_ORACLE_TIME_SELECT
                + ")"
                + SQL_ONE_LINE_COMMENT, // Param in WHERE clause somewhere
        "<<<<ORIGINALVALUE>>>> or exists ("
                + SQL_ORACLE_TIME_SELECT
                + ")"
                + SQL_ONE_LINE_COMMENT, // Param in WHERE clause somewhere
        "<<<<ORIGINALVALUE>>>>' or exists ("
                + SQL_ORACLE_TIME_SELECT
                + ")"
                + SQL_ONE_LINE_COMMENT, // Param in WHERE clause somewhere
        "<<<<ORIGINALVALUE>>>>\" or exists ("
                + SQL_ORACLE_TIME_SELECT
                + ")"
                + SQL_ONE_LINE_COMMENT, // Param in WHERE clause somewhere
        "<<<<ORIGINALVALUE>>>>) or exists ("
                + SQL_ORACLE_TIME_SELECT
                + ")"
                + SQL_ONE_LINE_COMMENT, // Param in WHERE clause somewhere
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

    /** for logging. */
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

        // set up what we are allowed to do, depending on the attack strength that was set.
        if (this.getAttackStrength() == AttackStrength.LOW) {
            doTimeMaxRequests = 3;
        } else if (this.getAttackStrength() == AttackStrength.MEDIUM) {
            doTimeMaxRequests = 5;
        } else if (this.getAttackStrength() == AttackStrength.HIGH) {
            doTimeMaxRequests = 10;
        } else if (this.getAttackStrength() == AttackStrength.INSANE) {
            doTimeMaxRequests = 100;
        }
    }

    /**
     * scans for SQL Injection vulnerabilities, using Oracle specific syntax. If it doesn't use
     * specifically Oracle syntax, it does not belong in here, but in SQLInjection
     */
    @Override
    public void scan(HttpMessage originalMessage, String paramName, String paramValue) {

        try {
            // Timing Baseline check: we need to get the time that it took the original query, to
            // know if the time based check is working correctly..
            HttpMessage msgTimeBaseline = getNewMsg();
            try {
                sendAndReceive(msgTimeBaseline, false); // do not follow redirects
            } catch (java.net.SocketTimeoutException e) {
                // to be expected occasionally, if the base query was one that contains some
                // parameters exploiting time based SQL injection?
                LOGGER.debug(
                        "The Base Time Check timed out on [{}] URL [{}]",
                        msgTimeBaseline.getRequestHeader().getMethod(),
                        msgTimeBaseline.getRequestHeader().getURI());
            }
            long originalTimeUsed = msgTimeBaseline.getTimeElapsedMillis();
            // end of timing baseline check

            int countTimeBasedRequests = 0;

            LOGGER.debug(
                    "Scanning URL [{}] [{}], field [{}] with value [{}] for Oracle SQL Injection",
                    getBaseMsg().getRequestHeader().getMethod(),
                    getBaseMsg().getRequestHeader().getURI(),
                    paramName,
                    paramValue);

            // Check for time based SQL Injection, using Oracle specific syntax
            for (int timeBasedSQLindex = 0;
                    timeBasedSQLindex < SQL_ORACLE_TIME_REPLACEMENTS.length
                            && countTimeBasedRequests < doTimeMaxRequests;
                    timeBasedSQLindex++) {
                HttpMessage msgAttack = getNewMsg();
                String newTimeBasedInjectionValue =
                        SQL_ORACLE_TIME_REPLACEMENTS[timeBasedSQLindex].replace(
                                "<<<<ORIGINALVALUE>>>>", paramValue);
                setParameter(msgAttack, paramName, newTimeBasedInjectionValue);
                // send it.
                try {
                    sendAndReceive(msgAttack, false); // do not follow redirects
                    countTimeBasedRequests++;
                } catch (java.net.SocketTimeoutException e) {
                    // this is to be expected, if we start sending slow queries to the database.
                    // ignore it in this case.. and just get the time.
                    LOGGER.debug(
                            "The time check query timed out on [{}] URL [{}] on field: [{}]",
                            msgTimeBaseline.getRequestHeader().getMethod(),
                            msgTimeBaseline.getRequestHeader().getURI(),
                            paramName);
                }
                long modifiedTimeUsed = msgAttack.getTimeElapsedMillis();

                LOGGER.debug(
                        "Time Based SQL Injection test: [{}] on field: [{}] with value [{}] took {}ms, where the original took {}ms",
                        newTimeBasedInjectionValue,
                        paramName,
                        newTimeBasedInjectionValue,
                        modifiedTimeUsed,
                        originalTimeUsed);

                if (modifiedTimeUsed >= (originalTimeUsed + expectedDelayInMs)) {
                    // takes more than 5 extra seconds => likely time based SQL injection.

                    // But first double check
                    HttpMessage msgc = getNewMsg();
                    try {
                        sendAndReceive(msgc, false); // do not follow redirects
                    } catch (Exception e) {
                        // Ignore all exceptions
                    }
                    long checkTimeUsed = msgc.getTimeElapsedMillis();
                    if (checkTimeUsed >= (originalTimeUsed + this.expectedDelayInMs - 200)) {
                        // Looks like the server is overloaded, very unlikely this is a real issue
                        continue;
                    }

                    String extraInfo =
                            Constant.messages.getString(
                                    "ascanrules.sqlinjection.alert.timebased.extrainfo",
                                    newTimeBasedInjectionValue,
                                    modifiedTimeUsed,
                                    paramValue,
                                    originalTimeUsed);
                    String attack =
                            Constant.messages.getString(
                                    "ascanrules.sqlinjection.alert.booleanbased.attack",
                                    paramName,
                                    newTimeBasedInjectionValue);

                    newAlert()
                            .setConfidence(Alert.CONFIDENCE_MEDIUM)
                            .setUri(getBaseMsg().getRequestHeader().getURI().toString())
                            .setName(getName() + " - Time Based")
                            .setParam(paramName)
                            .setAttack(attack)
                            .setOtherInfo(extraInfo)
                            .setMessage(msgAttack)
                            .raise();

                    LOGGER.debug(
                            "A likely Time Based SQL Injection Vulnerability has been found with [{}] URL [{}] on field: [{}]",
                            msgAttack.getRequestHeader().getMethod(),
                            msgAttack.getRequestHeader().getURI(),
                            paramName);
                    return;
                } // query took longer than the amount of time we attempted to retard it by
            } // for each time based SQL index
            // end of check for time based SQL Injection

        } catch (Exception e) {
            // Do not try to internationalise this.. we need an error message in any event..
            // if it's in English, it's still better than not having it at all.
            LOGGER.error(
                    "An error occurred checking a url for Oracle SQL Injection vulnerabilities", e);
        }
    }

    public void setExpectedDelayInMs(int delay) {
        expectedDelayInMs = delay;
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
