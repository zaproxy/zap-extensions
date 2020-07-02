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

import java.util.LinkedHashMap;
import java.util.Map;
import org.apache.commons.httpclient.InvalidRedirectLocationException;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;

/**
 * TODO: maybe implement a more specific UNION based check for Oracle (with table names)
 *
 * <p>The SqlInjectionOracleScanRule identifies Oracle specific SQL Injection vulnerabilities using
 * Oracle specific syntax. If it doesn't use Oracle specific syntax, it belongs in the generic
 * SQLInjection class! Note the ordering of checks, for efficiency is : 1) Error based (N/A) 2)
 * Boolean Based (N/A - uses standard syntax) 3) UNION based (TODO) 4) Stacked (N/A - uses standard
 * syntax) 5) Blind/Time Based (Yes)
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
public class SqlInjectionOracleScanRule extends AbstractAppParamPlugin {

    private boolean doUnionBased = false; // TODO: use in Union based, when we implement it
    private boolean doTimeBased = false;

    private int doUnionMaxRequests = 0; // TODO: use in Union based, when we implement it
    private int doTimeMaxRequests = 0;

    /** Oracle one-line comment */
    public static final String SQL_ONE_LINE_COMMENT = " -- ";

    /**
     * create a map of SQL related error message fragments, and map them back to the RDBMS that they
     * are associated with keep the ordering the same as the order in which the values are inserted,
     * to allow the more (subjectively judged) common cases to be tested first Note: these should
     * represent actual (driver level) error messages for things like syntax error, otherwise we are
     * simply guessing that the string should/might occur.
     */
    private static final Map<String, String> SQL_ERROR_TO_DBMS = new LinkedHashMap<>();

    static {
        SQL_ERROR_TO_DBMS.put("oracle.jdbc", "Oracle");
        SQL_ERROR_TO_DBMS.put("SQLSTATE[HY", "Oracle");
        SQL_ERROR_TO_DBMS.put("ORA-00933", "Oracle");
        SQL_ERROR_TO_DBMS.put("ORA-06512", "Oracle"); // indicates the line number of an error
        SQL_ERROR_TO_DBMS.put("SQL command not properly ended", "Oracle");
        SQL_ERROR_TO_DBMS.put("ORA-00942", "Oracle"); // table or view does not exist
        SQL_ERROR_TO_DBMS.put("ORA-29257", "Oracle"); // host unknown
        SQL_ERROR_TO_DBMS.put("ORA-00932", "Oracle"); // inconsistent datatypes

        // Note: only Oracle mappings here.
        // TODO: is this all?? we need more error messages for Oracle for different languages. PHP
        // (oci8), ASP, JSP(JDBC), etc
    }

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

    /** for logging. */
    private static Logger log = Logger.getLogger(SqlInjectionOracleScanRule.class);

    /** determines if we should output Debug level logging */
    private boolean debugEnabled = log.isDebugEnabled();

    @Override
    public int getId() {
        return 40021;
    }

    @Override
    public String getName() {
        return Constant.messages.getString("ascanbeta.sqlinjection.oracle.name");
    }

    @Override
    public boolean targets(TechSet technologies) {
        return technologies.includes(Tech.Oracle);
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
        // DEBUG: turn on for debugging
        // TODO: turn this off
        // log.setLevel(org.apache.log4j.Level.DEBUG);
        // this.debugEnabled = true;

        if (this.debugEnabled) log.debug("Initialising");

        // TODO: debug only
        // this.setAttackStrength(AttackStrength.INSANE);

        // set up what we are allowed to do, depending on the attack strength that was set.
        if (this.getAttackStrength() == AttackStrength.LOW) {
            doTimeBased = true;
            doTimeMaxRequests = 3;
            doUnionBased = true;
            doUnionMaxRequests = 3;
        } else if (this.getAttackStrength() == AttackStrength.MEDIUM) {
            doTimeBased = true;
            doTimeMaxRequests = 5;
            doUnionBased = true;
            doUnionMaxRequests = 5;
        } else if (this.getAttackStrength() == AttackStrength.HIGH) {
            doTimeBased = true;
            doTimeMaxRequests = 10;
            doUnionBased = true;
            doUnionMaxRequests = 10;
        } else if (this.getAttackStrength() == AttackStrength.INSANE) {
            doTimeBased = true;
            doTimeMaxRequests = 100;
            doUnionBased = true;
            doUnionMaxRequests = 100;
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
            }
            long originalTimeUsed = System.currentTimeMillis() - originalTimeStarted;
            // end of timing baseline check

            int countUnionBasedRequests = 0;
            int countTimeBasedRequests = 0;

            if (this.debugEnabled)
                log.debug(
                        "Scanning URL ["
                                + getBaseMsg().getRequestHeader().getMethod()
                                + "] ["
                                + getBaseMsg().getRequestHeader().getURI()
                                + "], field ["
                                + paramName
                                + "] with value ["
                                + paramValue
                                + "] for Oracle SQL Injection");

            // Check for time based SQL Injection, using Oracle specific syntax
            for (int timeBasedSQLindex = 0;
                    timeBasedSQLindex < SQL_ORACLE_TIME_REPLACEMENTS.length
                            && doTimeBased
                            && countTimeBasedRequests < doTimeMaxRequests;
                    timeBasedSQLindex++) {
                HttpMessage msgAttack = getNewMsg();
                String newTimeBasedInjectionValue =
                        SQL_ORACLE_TIME_REPLACEMENTS[timeBasedSQLindex].replace(
                                "<<<<ORIGINALVALUE>>>>", paramValue);
                setParameter(msgAttack, paramName, newTimeBasedInjectionValue);
                // send it.
                long modifiedTimeStarted = System.currentTimeMillis();
                try {
                    sendAndReceive(msgAttack, false); // do not follow redirects
                    countTimeBasedRequests++;
                } catch (java.net.SocketTimeoutException e) {
                    // this is to be expected, if we start sending slow queries to the database.
                    // ignore it in this case.. and just get the time.
                    if (this.debugEnabled)
                        log.debug(
                                "The time check query timed out on ["
                                        + msgTimeBaseline.getRequestHeader().getMethod()
                                        + "] URL ["
                                        + msgTimeBaseline.getRequestHeader().getURI().getURI()
                                        + "] on field: ["
                                        + paramName
                                        + "]");
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

                if (modifiedTimeUsed >= (originalTimeUsed + 5000)) {
                    // takes more than 5 extra seconds => likely time based SQL injection. Raise it
                    String extraInfo =
                            Constant.messages.getString(
                                    "ascanbeta.sqlinjection.alert.timebased.extrainfo",
                                    newTimeBasedInjectionValue,
                                    modifiedTimeUsed,
                                    paramValue,
                                    originalTimeUsed);
                    String attack =
                            Constant.messages.getString(
                                    "ascanbeta.sqlinjection.alert.booleanbased.attack",
                                    paramName,
                                    newTimeBasedInjectionValue);

                    newAlert()
                            .setConfidence(Alert.CONFIDENCE_MEDIUM)
                            .setUri(getBaseMsg().getRequestHeader().getURI().getURI())
                            .setName(getName() + " - Time Based")
                            .setParam(paramName)
                            .setAttack(attack)
                            .setOtherInfo(extraInfo)
                            .setMessage(msgAttack)
                            .raise();

                    if (log.isDebugEnabled()) {
                        log.debug(
                                "A likely Time Based SQL Injection Vulnerability has been found with ["
                                        + msgAttack.getRequestHeader().getMethod()
                                        + "] URL ["
                                        + msgAttack.getRequestHeader().getURI().getURI()
                                        + "] on field: ["
                                        + paramName
                                        + "]");
                    }
                    return;
                } // query took longer than the amount of time we attempted to retard it by
            } // for each time based SQL index
            // end of check for time based SQL Injection

        } catch (InvalidRedirectLocationException e) {
            // Not an error, just means we probably attacked the redirect location
        } catch (Exception e) {
            // Do not try to internationalise this.. we need an error message in any event..
            // if it's in English, it's still better than not having it at all.
            log.error(
                    "An error occurred checking a url for Oracle SQL Injection vulnerabilities", e);
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
