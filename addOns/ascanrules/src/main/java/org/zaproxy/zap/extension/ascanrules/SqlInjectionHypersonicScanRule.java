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
 * TODO: maybe implement a more specific UNION based check for Hypersonic (with table names)
 *
 * <p>The SqlInjectionHypersonicScanRule identifies Hypersonic specific SQL Injection
 * vulnerabilities using Hypersonic specific syntax. If it doesn't use Hypersonic specific syntax,
 * it belongs in the generic SQLInjection class! Note the ordering of checks, for efficiency is : 1)
 * Error based (N/A) 2) Boolean Based (N/A - uses standard syntax) 3) UNION based (TODO) 4) Stacked
 * (N/A - uses standard syntax) 5) Blind/Time Based (Yes)
 *
 * <p>See the following for some great (non-Hypersonic specific) specific tricks which could be
 * integrated here http://www.websec.ca/kb/sql_injection
 * http://pentestmonkey.net/cheat-sheet/sql-injection/oracle-sql-injection-cheat-sheet
 *
 * <p>Important Notes for the Hypersonic database (and useful in the code): - takes -- style
 * comments - requires a table name in normal select statements (like Oracle: cannot just say
 * "select 1" or "select 2" like in most RDBMSs - requires a table name in "union select" statements
 * (like Oracle). - allows stacked queries via JDBC driver. - Constants in select must be in single
 * quotes, not doubles (like Oracle). - supports UDFs in the form of Java code (very interesting!!)
 * - x second delay select statement: select "java.lang.Thread.sleep"(5000) from
 * INFORMATION_SCHEMA.SYSTEM_COLUMNS where TABLE_NAME = 'SYSTEM_COLUMNS' and COLUMN_NAME =
 * 'TABLE_NAME' - metadata select statement: select TABLE_NAME, COLUMN_NAME, TYPE_NAME, COLUMN_SIZE,
 * DECIMAL_DIGITS, IS_NULLABLE from INFORMATION_SCHEMA.SYSTEM_COLUMNS
 *
 * @author 70pointer
 */
public class SqlInjectionHypersonicScanRule extends AbstractAppParamPlugin
        implements CommonActiveScanRuleInfo {

    /** Hypersonic one-line comment */
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
        SQL_ERROR_TO_DBMS.put("org.hsql", "Hypersonic SQL");
        SQL_ERROR_TO_DBMS.put("hSql.", "Hypersonic SQL");
        SQL_ERROR_TO_DBMS.put("Unexpected token , requires FROM in statement", "Hypersonic SQL");
        SQL_ERROR_TO_DBMS.put("Unexpected end of command in statement", "Hypersonic SQL");
        SQL_ERROR_TO_DBMS.put("Column count does not match in statement", "Hypersonic SQL");
        SQL_ERROR_TO_DBMS.put("Table not found in statement", "Hypersonic SQL");
        SQL_ERROR_TO_DBMS.put("Unexpected token:", "Hypersonic SQL");
        // Note: only Hypersonic mappings here.
    }

    /** the sleep function in Hypersonic SQL */
    private static final String SQL_HYPERSONIC_TIME_FUNCTION =
            "\"java.lang.Thread.sleep\"(" + SLEEP_TOKEN + ")";

    /** Hypersonic specific time based injection strings. */

    // issue with "+" symbols in here:
    // we cannot encode them here as %2B, as then the database gets them double encoded as %252Bn
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
    private static final List<String> SQL_HYPERSONIC_TIME_REPLACEMENTS =
            List.of(
                    "; select "
                            + SQL_HYPERSONIC_TIME_FUNCTION
                            + " from INFORMATION_SCHEMA.SYSTEM_COLUMNS where TABLE_NAME = 'SYSTEM_COLUMNS' and COLUMN_NAME = 'TABLE_NAME'"
                            + SQL_ONE_LINE_COMMENT,
                    "'; select "
                            + SQL_HYPERSONIC_TIME_FUNCTION
                            + " from INFORMATION_SCHEMA.SYSTEM_COLUMNS where TABLE_NAME = 'SYSTEM_COLUMNS' and COLUMN_NAME = 'TABLE_NAME'"
                            + SQL_ONE_LINE_COMMENT,
                    "\"; select "
                            + SQL_HYPERSONIC_TIME_FUNCTION
                            + " from INFORMATION_SCHEMA.SYSTEM_COLUMNS where TABLE_NAME = 'SYSTEM_COLUMNS' and COLUMN_NAME = 'TABLE_NAME'"
                            + SQL_ONE_LINE_COMMENT,
                    "); select "
                            + SQL_HYPERSONIC_TIME_FUNCTION
                            + " from INFORMATION_SCHEMA.SYSTEM_COLUMNS where TABLE_NAME = 'SYSTEM_COLUMNS' and COLUMN_NAME = 'TABLE_NAME'"
                            + SQL_ONE_LINE_COMMENT,
                    SQL_HYPERSONIC_TIME_FUNCTION,
                    ORIG_VALUE_TOKEN + " / " + SQL_HYPERSONIC_TIME_FUNCTION + " ",
                    ORIG_VALUE_TOKEN + "' / " + SQL_HYPERSONIC_TIME_FUNCTION + " / '",
                    ORIG_VALUE_TOKEN + "\" / " + SQL_HYPERSONIC_TIME_FUNCTION + " / \"",
                    ORIG_VALUE_TOKEN
                            + " and exists ( select "
                            + SQL_HYPERSONIC_TIME_FUNCTION
                            + " from INFORMATION_SCHEMA.SYSTEM_COLUMNS where TABLE_NAME = 'SYSTEM_COLUMNS' and COLUMN_NAME = 'TABLE_NAME')"
                            + SQL_ONE_LINE_COMMENT, // Param in WHERE clause somewhere
                    ORIG_VALUE_TOKEN
                            + "' and exists ( select "
                            + SQL_HYPERSONIC_TIME_FUNCTION
                            + " from INFORMATION_SCHEMA.SYSTEM_COLUMNS where TABLE_NAME = 'SYSTEM_COLUMNS' and COLUMN_NAME = 'TABLE_NAME')"
                            + SQL_ONE_LINE_COMMENT, // Param in WHERE clause somewhere
                    ORIG_VALUE_TOKEN
                            + "\" and exists ( select "
                            + SQL_HYPERSONIC_TIME_FUNCTION
                            + " from INFORMATION_SCHEMA.SYSTEM_COLUMNS where TABLE_NAME = 'SYSTEM_COLUMNS' and COLUMN_NAME = 'TABLE_NAME')"
                            + SQL_ONE_LINE_COMMENT, // Param in WHERE clause somewhere
                    ORIG_VALUE_TOKEN
                            + ") and exists ( select "
                            + SQL_HYPERSONIC_TIME_FUNCTION
                            + " from INFORMATION_SCHEMA.SYSTEM_COLUMNS where TABLE_NAME = 'SYSTEM_COLUMNS' and COLUMN_NAME = 'TABLE_NAME')"
                            + SQL_ONE_LINE_COMMENT, // Param in WHERE clause somewhere
                    ORIG_VALUE_TOKEN
                            + " or exists ( select "
                            + SQL_HYPERSONIC_TIME_FUNCTION
                            + " from INFORMATION_SCHEMA.SYSTEM_COLUMNS where TABLE_NAME = 'SYSTEM_COLUMNS' and COLUMN_NAME = 'TABLE_NAME')"
                            + SQL_ONE_LINE_COMMENT, // Param in WHERE clause somewhere
                    ORIG_VALUE_TOKEN
                            + "' or exists ( select "
                            + SQL_HYPERSONIC_TIME_FUNCTION
                            + " from INFORMATION_SCHEMA.SYSTEM_COLUMNS where TABLE_NAME = 'SYSTEM_COLUMNS' and COLUMN_NAME = 'TABLE_NAME')"
                            + SQL_ONE_LINE_COMMENT, // Param in WHERE clause somewhere
                    ORIG_VALUE_TOKEN
                            + "\" or exists ( select "
                            + SQL_HYPERSONIC_TIME_FUNCTION
                            + " from INFORMATION_SCHEMA.SYSTEM_COLUMNS where TABLE_NAME = 'SYSTEM_COLUMNS' and COLUMN_NAME = 'TABLE_NAME')"
                            + SQL_ONE_LINE_COMMENT, // Param in WHERE clause somewhere
                    ORIG_VALUE_TOKEN
                            + ") or exists ( select "
                            + SQL_HYPERSONIC_TIME_FUNCTION
                            + " from INFORMATION_SCHEMA.SYSTEM_COLUMNS where TABLE_NAME = 'SYSTEM_COLUMNS' and COLUMN_NAME = 'TABLE_NAME')"
                            + SQL_ONE_LINE_COMMENT // Param in WHERE clause somewhere
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
    private static final Logger LOGGER = LogManager.getLogger(SqlInjectionHypersonicScanRule.class);

    /** The number of seconds used in time-based attacks (i.e. sleep commands). */
    private int timeSleepSeconds = DEFAULT_SLEEP_TIME;

    private int blindTargetCount = SQL_HYPERSONIC_TIME_REPLACEMENTS.size();

    @Override
    public int getId() {
        return 40020;
    }

    @Override
    public String getName() {
        return Constant.messages.getString("ascanrules.sqlinjection.hypersonic.name");
    }

    @Override
    public boolean targets(TechSet technologies) {
        return technologies.includes(Tech.HypersonicSQL);
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
            blindTargetCount = SQL_HYPERSONIC_TIME_REPLACEMENTS.size();
        }

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
     * scans for SQL Injection vulnerabilities, using Hypersonic specific syntax. If it doesn't use
     * specifically Hypersonic syntax, it does not belong in here, but in SQLInjection
     */
    @Override
    public void scan(HttpMessage originalMessage, String paramName, String paramValue) {

        LOGGER.debug(
                "Scanning URL [{}] [{}], field [{}] with value [{}] for SQL Injection",
                getBaseMsg().getRequestHeader().getMethod(),
                getBaseMsg().getRequestHeader().getURI(),
                paramName,
                paramValue);

        Iterator<String> it = SQL_HYPERSONIC_TIME_REPLACEMENTS.iterator();
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
                                        // Time in milliseconds for the SQL function.
                                        .replace(SLEEP_TOKEN, Integer.toString(((int) x) * 1000));

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
                                    paramValue,
                                    getBaseMsg().getTimeElapsedMillis());

                    newAlert()
                            .setConfidence(Alert.CONFIDENCE_MEDIUM)
                            .setName(getName() + " - Time Based")
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

    void setTimeSleepSeconds(int timeSleepSeconds) {
        this.timeSleepSeconds = timeSleepSeconds;
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
