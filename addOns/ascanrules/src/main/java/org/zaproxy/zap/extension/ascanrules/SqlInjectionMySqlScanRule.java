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
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
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
 * The SqlInjectionMySqlScanRule identifies MySQL specific SQL Injection vulnerabilities using MySQL
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
public class SqlInjectionMySqlScanRule extends AbstractAppParamPlugin
        implements CommonActiveScanRuleInfo {

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
    private static final List<String> SQL_MYSQL_TIME_REPLACEMENTS =
            List.of(
                    // LOW
                    ORIG_VALUE_TOKEN
                            + " / sleep("
                            + SLEEP_TOKEN
                            + ") ", // MySQL >= 5.0.12. Might work if "SET
                    // sql_mode='STRICT_TRANS_TABLES'" is
                    // OFF. Try without a comment, to target use of the field in the SELECT
                    // clause, but also in the WHERE clauses.
                    ORIG_VALUE_TOKEN
                            + "' / sleep("
                            + SLEEP_TOKEN
                            + ") / '", // MySQL >= 5.0.12. Might work if "SET
                    // sql_mode='STRICT_TRANS_TABLES'" is
                    // OFF. Try without a comment, to target use of the field in the SELECT
                    // clause, but also in the WHERE clauses.
                    ORIG_VALUE_TOKEN
                            + "\" / sleep("
                            + SLEEP_TOKEN
                            + ") / \"", // MySQL >= 5.0.12. Might work if "SET
                    // sql_mode='STRICT_TRANS_TABLES'"
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
                            + SQL_ONE_LINE_COMMENT, // MySQL >= 5.0.12. Param in
                    // SELECT/UPDATE/DELETE clause.
                    ORIG_VALUE_TOKEN
                            + "' where 0 in (select sleep("
                            + SLEEP_TOKEN
                            + ") )"
                            + SQL_ONE_LINE_COMMENT, // MySQL >= 5.0.12. Param in
                    // SELECT/UPDATE/DELETE clause.
                    ORIG_VALUE_TOKEN
                            + "\" where 0 in (select sleep("
                            + SLEEP_TOKEN
                            + ") )"
                            + SQL_ONE_LINE_COMMENT, // MySQL >= 5.0.12. Param in
                    // SELECT/UPDATE/DELETE clause.
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
                            + ") ) and ''='", // MySQL >= 5.0.12. Param in SELECT/UPDATE/DELETE
                    // clause.
                    ORIG_VALUE_TOKEN
                            + "\" where 0 in (select sleep("
                            + SLEEP_TOKEN
                            + ") ) and \"\"=\"", // MySQL >= 5.0.12. Param in SELECT/UPDATE/DELETE
                    // clause.
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
                            + ") ) and \"\"=\"" // MySQL >= 5.0.12. Param in WHERE clause.
                    );

    /** The default number of seconds used in time-based attacks (i.e. sleep commands). */
    private static final int DEFAULT_SLEEP_TIME = 5;

    // limit the maximum number of requests sent for time-based attack detection
    private static final int BLIND_REQUESTS_LIMIT = 4;

    // error range allowable for statistical time-based blind attacks (0-1.0)
    private static final double TIME_CORRELATION_ERROR_RANGE = 0.15;
    private static final double TIME_SLOPE_ERROR_RANGE = 0.30;

    private static final Map<String, String> ALERT_TAGS =
            CommonAlertTag.toMap(
                    CommonAlertTag.OWASP_2021_A03_INJECTION,
                    CommonAlertTag.OWASP_2017_A01_INJECTION,
                    CommonAlertTag.WSTG_V42_INPV_05_SQLI);

    /** for logging. */
    private static final Logger LOGGER = LogManager.getLogger(SqlInjectionMySqlScanRule.class);

    private int timeSleepSeconds = DEFAULT_SLEEP_TIME;

    private int blindTargetCount = SQL_MYSQL_TIME_REPLACEMENTS.size();

    @Override
    public int getId() {
        return 40019;
    }

    @Override
    public String getName() {
        return Constant.messages.getString("ascanrules.sqlinjection.mysql.name");
    }

    @Override
    public boolean targets(TechSet technologies) {
        return technologies.includes(Tech.MySQL);
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
            blindTargetCount = SQL_MYSQL_TIME_REPLACEMENTS.size();
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

    /**
     * scans for SQL Injection vulnerabilities, using MySQL specific syntax. If it doesn't use
     * specifically MySQL syntax, it does not belong in here, but in TestSQLInjection
     */
    @Override
    public void scan(HttpMessage originalMessage, String paramName, String originalParamValue) {

        LOGGER.debug(
                "Scanning URL [{}] [{}], field [{}] with value [{}] for SQL Injection",
                getBaseMsg().getRequestHeader().getMethod(),
                getBaseMsg().getRequestHeader().getURI(),
                paramName,
                originalParamValue);

        Iterator<String> it = SQL_MYSQL_TIME_REPLACEMENTS.iterator();
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
                                        .replace(ORIG_VALUE_TOKEN, originalParamValue)
                                        .replace(SLEEP_TOKEN, Integer.toString((int) x));

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
                                    "ascanrules.sqlinjection.alert.timebased.extrainfo",
                                    attack.get(),
                                    message.get().getTimeElapsedMillis(),
                                    originalParamValue,
                                    getBaseMsg().getTimeElapsedMillis());

                    // raise the alert
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

    public void setSleepInSeconds(int sleep) {
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
