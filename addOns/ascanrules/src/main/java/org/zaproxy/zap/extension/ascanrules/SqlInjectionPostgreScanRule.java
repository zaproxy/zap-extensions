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
import java.net.SocketException;
import java.util.LinkedHashMap;
import java.util.Map;
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
 * The SqlInjectionPostgreScanRule identifies Postgresql specific SQL Injection vulnerabilities
 * using Postgresql specific syntax. If it doesn't use Postgresql specific syntax, it belongs in the
 * generic SQLInjection class! Note the ordering of checks, for efficiency is : 1) Error based (N/A)
 * 2) Boolean Based (N/A - uses standard syntax) 3) UNION based (N/A - uses standard syntax) 4)
 * Stacked (N/A - uses standard syntax) 5) Blind/Time Based (Yes)
 *
 * <p>See the following for some great specific tricks which could be integrated here
 * http://www.websec.ca/kb/sql_injection
 * http://pentestmonkey.net/cheat-sheet/sql-injection/postgres-sql-injection-cheat-sheet
 *
 * <p>Important Notes for the POSTGRES database (and useful in the code): - takes -- style comments
 * - allows stacked queries via JDBC driver or in PHP??? - Constants in select must be in single
 * quotes, not doubles (like Hypersonic). - supports UDFs (very interesting!!) - 5 (by default)
 * second delay select statement (not taking into account casting, etc.): SELECT pg_sleep(5) -
 * metadata select statement: TODO
 *
 * @author 70pointer
 */
public class SqlInjectionPostgreScanRule extends AbstractAppParamPlugin
        implements CommonActiveScanRuleInfo {

    private boolean doTimeBased = false;

    private int doTimeMaxRequests = 0;

    private int sleepInSeconds;

    /** Postgresql one-line comment */
    public static final String SQL_ONE_LINE_COMMENT = " -- ";

    private static final String ORIG_VALUE_TOKEN = "<<<<ORIGINALVALUE>>>>";
    private static final String SLEEP_TOKEN = "<<<<SLEEP>>>>";
    private static final int DEFAULT_TIME_SLEEP_SEC = 5;
    private static final int BLIND_REQUEST_LIMIT = 4;
    // error range allowable for statistical time-based blind attacks (0-1.0)
    private static final double TIME_CORRELATION_ERROR_RANGE = 0.15;
    private static final double TIME_SLOPE_ERROR_RANGE = 0.30;

    /**
     * create a map of SQL related error message fragments, and map them back to the RDBMS that they
     * are associated with keep the ordering the same as the order in which the values are inserted,
     * to allow the more (subjectively judged) common cases to be tested first Note: these should
     * represent actual (driver level) error messages for things like syntax error, otherwise we are
     * simply guessing that the string should/might occur.
     */
    private static final Map<String, String> SQL_ERROR_TO_DBMS = new LinkedHashMap<>();

    static {
        SQL_ERROR_TO_DBMS.put("org.postgresql.util.PSQLException", "PostgreSQL");
        SQL_ERROR_TO_DBMS.put("org.postgresql", "PostgreSQL");
        // Note: only Postgresql mappings here.
        // TODO: is this all?? we need more error messages for Postgresql for different languages.
        // PHP, ASP, JSP(JDBC), etc.
    }

    /**
     * The sleep function in Postgresql cast it back to an int, so we can use it in nested select
     * statements and stuff.
     */
    private static String SQL_POSTGRES_TIME_FUNCTION =
            "case when cast(pg_sleep(" + SLEEP_TOKEN + ") as varchar) > '' then 0 else 1 end";

    /** Postgres specific time based injection strings. */

    // issue with "+" symbols in here:
    // we cannot encode them here as %2B, as then the database gets them double encoded as %252B
    // we cannot leave them as unencoded '+' characters either, as then they are NOT encoded by the
    // HttpMessage.setGetParams (x) or by AbstractPlugin.sendAndReceive (HttpMessage)
    // and are seen by the database as spaces :(
    // in short, we cannot use the "+" character in parameters, unless we mean to use it as a space
    // character!!!! Particularly Nasty.
    // Workaround: use RDBMS specific functions like "CONCAT(a,b,c)" which mean parsing the original
    // value into the middle of the parameter value to be passed,
    // rather than just appending to it
    // Issue: this technique does not close the open ' or " in the query.. so do not use it..
    // Note: <<<<ORIGINALVALUE>>>> is replaced with the original parameter value at runtime in these
    // examples below (see * comment)
    // TODO: maybe add support for ')' after the original value, before the sleeps

    private static String[] SQL_POSTGRES_TIME_REPLACEMENTS = {
        SQL_POSTGRES_TIME_FUNCTION,
        SQL_POSTGRES_TIME_FUNCTION + SQL_ONE_LINE_COMMENT,
        "'" + SQL_POSTGRES_TIME_FUNCTION + SQL_ONE_LINE_COMMENT,
        "\"" + SQL_POSTGRES_TIME_FUNCTION + SQL_ONE_LINE_COMMENT,
        ORIG_VALUE_TOKEN
                + " / "
                + SQL_POSTGRES_TIME_FUNCTION
                + " ", // Try without a comment, to target use of the field in the SELECT clause,
        // but also in the WHERE clauses.
        ORIG_VALUE_TOKEN
                + "' / "
                + SQL_POSTGRES_TIME_FUNCTION
                + " / '", // Try without a comment, to target use of the field in the SELECT clause,
        // but also in the WHERE clauses.
        ORIG_VALUE_TOKEN
                + "\" / "
                + SQL_POSTGRES_TIME_FUNCTION
                + " / \"", // Try without a comment, to target use of the field in the SELECT
        // clause, but also in the WHERE clauses.
        ORIG_VALUE_TOKEN
                + " where 0 in (select "
                + SQL_POSTGRES_TIME_FUNCTION
                + " )"
                + SQL_ONE_LINE_COMMENT, // Param in SELECT/UPDATE/DELETE clause.
        ORIG_VALUE_TOKEN
                + "' where 0 in (select "
                + SQL_POSTGRES_TIME_FUNCTION
                + " )"
                + SQL_ONE_LINE_COMMENT, // Param in SELECT/UPDATE/DELETE clause.
        ORIG_VALUE_TOKEN
                + "\" where 0 in (select "
                + SQL_POSTGRES_TIME_FUNCTION
                + " )"
                + SQL_ONE_LINE_COMMENT, // Param in SELECT/UPDATE/DELETE clause.
        ORIG_VALUE_TOKEN
                + " and 0 in (select "
                + SQL_POSTGRES_TIME_FUNCTION
                + " )"
                + SQL_ONE_LINE_COMMENT, // Param in WHERE clause.
        ORIG_VALUE_TOKEN
                + "' and 0 in (select "
                + SQL_POSTGRES_TIME_FUNCTION
                + " )"
                + SQL_ONE_LINE_COMMENT, // Param in WHERE clause.
        ORIG_VALUE_TOKEN
                + "\" and 0 in (select "
                + SQL_POSTGRES_TIME_FUNCTION
                + " )"
                + SQL_ONE_LINE_COMMENT, // Param in WHERE clause.
        ORIG_VALUE_TOKEN
                + " or 0 in (select "
                + SQL_POSTGRES_TIME_FUNCTION
                + " )"
                + SQL_ONE_LINE_COMMENT, // Param in WHERE clause.
        ORIG_VALUE_TOKEN
                + "' or 0 in (select "
                + SQL_POSTGRES_TIME_FUNCTION
                + " )"
                + SQL_ONE_LINE_COMMENT, // Param in WHERE clause.
        ORIG_VALUE_TOKEN
                + "\" or 0 in (select "
                + SQL_POSTGRES_TIME_FUNCTION
                + " )"
                + SQL_ONE_LINE_COMMENT, // Param in WHERE clause.
    };

    private static final Map<String, String> ALERT_TAGS =
            CommonAlertTag.toMap(
                    CommonAlertTag.OWASP_2021_A03_INJECTION,
                    CommonAlertTag.OWASP_2017_A01_INJECTION,
                    CommonAlertTag.WSTG_V42_INPV_05_SQLI);

    /** for logging. */
    private static final Logger LOGGER = LogManager.getLogger(SqlInjectionPostgreScanRule.class);

    @Override
    public int getId() {
        return 40022;
    }

    @Override
    public String getName() {
        return Constant.messages.getString("ascanrules.sqlinjection.postgres.name");
    }

    @Override
    public boolean targets(TechSet technologies) {
        return technologies.includes(Tech.PostgreSQL);
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
            doTimeBased = true;
            doTimeMaxRequests = 3;
        } else if (this.getAttackStrength() == AttackStrength.MEDIUM) {
            doTimeBased = true;
            doTimeMaxRequests = 5;
        } else if (this.getAttackStrength() == AttackStrength.HIGH) {
            doTimeBased = true;
            doTimeMaxRequests = 10;
        } else if (this.getAttackStrength() == AttackStrength.INSANE) {
            doTimeBased = true;
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

    /**
     * scans for SQL Injection vulnerabilities, using POSTGRES specific syntax. If it doesn't use
     * specifically POSTGRES syntax, it does not belong in here, but in SQLInjection
     */
    @Override
    public void scan(HttpMessage originalMessage, String paramName, String paramValue) {
        try {
            // Timing Baseline check: we need to get the time that it took the original query, to
            // know if the time based check is working correctly..
            int countTimeBasedRequests = 0;
            for (int timeBasedSQLindex = 0;
                    timeBasedSQLindex < SQL_POSTGRES_TIME_REPLACEMENTS.length
                            && doTimeBased
                            && countTimeBasedRequests < doTimeMaxRequests;
                    timeBasedSQLindex++) {
                countTimeBasedRequests++;
                AtomicReference<HttpMessage> message = new AtomicReference<>();
                String payloadValue =
                        SQL_POSTGRES_TIME_REPLACEMENTS[timeBasedSQLindex].replace(
                                ORIG_VALUE_TOKEN, paramValue);
                TimingUtils.RequestSender requestSender =
                        x -> {
                            HttpMessage timedMsg = getNewMsg();
                            message.compareAndSet(null, timedMsg);
                            String finalPayload =
                                    payloadValue.replace(SLEEP_TOKEN, String.valueOf(x));
                            setParameter(timedMsg, paramName, finalPayload);
                            // send the request and retrieve the response
                            sendAndReceive(timedMsg, false); // do not follow redirects
                            return timedMsg.getTimeElapsedMillis() / 1000.0;
                        };
                boolean isInjectable;
                try {
                    try {
                        // use TimingUtils to detect a response to sleep payloads
                        isInjectable =
                                TimingUtils.checkTimingDependence(
                                        BLIND_REQUEST_LIMIT,
                                        sleepInSeconds,
                                        requestSender,
                                        TIME_CORRELATION_ERROR_RANGE,
                                        TIME_SLOPE_ERROR_RANGE);
                    } catch (SocketException ex) {
                        LOGGER.debug(
                                "Caught {} {} when accessing: {}.\n The target may have replied with a poorly formed redirect due to our input.",
                                ex.getClass().getName(),
                                ex.getMessage(),
                                message.get().getRequestHeader().getURI());
                        continue; // Something went wrong, move to next blind iteration
                    }

                    if (isInjectable) {
                        String finalPayloadValue =
                                payloadValue.replace(SLEEP_TOKEN, String.valueOf(sleepInSeconds));
                        // We Found IT!
                        String extraInfo =
                                Constant.messages.getString(
                                        "ascanrules.sqlinjection.alert.timebased.extrainfo",
                                        finalPayloadValue,
                                        message.get().getTimeElapsedMillis(),
                                        paramValue,
                                        getBaseMsg().getTimeElapsedMillis());
                        String attack =
                                Constant.messages.getString(
                                        "ascanrules.sqlinjection.alert.booleanbased.attack",
                                        paramName,
                                        finalPayloadValue);
                        LOGGER.debug(
                                "[Time Based Postrgres SQL Injection - Found] on parameter [{}] with value [{}]",
                                paramName,
                                paramValue);

                        newAlert()
                                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                                .setName(getName() + " - Time Based")
                                .setUri(getBaseMsg().getRequestHeader().getURI().toString())
                                .setParam(paramName)
                                .setAttack(attack)
                                .setMessage(message.get())
                                .setOtherInfo(extraInfo)
                                .raise();
                        return;
                    }
                } catch (IOException ex) {
                    LOGGER.warn(
                            "Time based postgres SQL Injection vulnerability check failed for parameter [{}] and payload [{}] due to an I/O error",
                            paramName,
                            paramValue,
                            ex);
                }
            }

        } catch (Exception e) {
            // Do not try to internationalise this.. we need an error message in any event..
            // if it's in English, it's still better than not having it at all.
            LOGGER.error(
                    "An error occurred checking a url for POSTGRES SQL Injection vulnerabilities",
                    e);
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
