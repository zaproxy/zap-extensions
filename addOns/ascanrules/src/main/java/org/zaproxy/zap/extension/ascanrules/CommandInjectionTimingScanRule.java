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
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.apache.commons.configuration.ConversionException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.timing.TimingUtils;
import org.zaproxy.zap.extension.ruleconfig.RuleConfigParam;
import org.zaproxy.zap.model.Tech;

/** Active scan rule for time based Command Injection testing and verification. */
public class CommandInjectionTimingScanRule extends CommandInjectionScanRule
        implements CommonActiveScanRuleInfo {

    private static final int PLUGIN_ID = 90037;

    /** The name of the rule config to obtain the time, in seconds, for time-based attacks. */
    private static final String RULE_SLEEP_TIME = RuleConfigParam.RULE_COMMON_SLEEP_TIME;

    private static final Map<String, String> ALERT_TAGS;

    static {
        Map<String, String> alertTags =
                new HashMap<>(CommonAlertTag.toMap(CommonAlertTag.TEST_TIMING));
        alertTags.putAll(CommandInjectionScanRule.ALERT_TAGS);
        ALERT_TAGS = Collections.unmodifiableMap(alertTags);
    }

    /** The default number of seconds used in time-based attacks (i.e. sleep commands). */
    private static final int DEFAULT_TIME_SLEEP_SEC = 5;

    // limit the maximum number of requests sent for time-based attack detection
    private static final int BLIND_REQUESTS_LIMIT = 4;

    // error range allowable for statistical time-based blind attacks (0-1.0)
    private static final double TIME_CORRELATION_ERROR_RANGE = 0.15;
    private static final double TIME_SLOPE_ERROR_RANGE = 0.30;

    // *NIX Blind OS Command constants
    private static final String NIX_BLIND_TEST_CMD = "sleep {0}";
    // Windows Blind OS Command constants
    private static final String WIN_BLIND_TEST_CMD = "timeout /T {0}";
    // PowerSHell Blind Command constants
    private static final String PS_BLIND_TEST_CMD = "start-sleep -s {0}";

    // OS Command payloads for blind command Injection testing
    private static final List<String> NIX_BLIND_OS_PAYLOADS = new LinkedList<>();
    private static final List<String> WIN_BLIND_OS_PAYLOADS = new LinkedList<>();
    private static final List<String> PS_BLIND_PAYLOADS = new LinkedList<>();

    static {
        // No quote payloads
        NIX_BLIND_OS_PAYLOADS.add("&" + NIX_BLIND_TEST_CMD + "&");
        NIX_BLIND_OS_PAYLOADS.add(";" + NIX_BLIND_TEST_CMD + ";");
        WIN_BLIND_OS_PAYLOADS.add("&" + WIN_BLIND_TEST_CMD);
        WIN_BLIND_OS_PAYLOADS.add("|" + WIN_BLIND_TEST_CMD);
        PS_BLIND_PAYLOADS.add(";" + PS_BLIND_TEST_CMD);

        // Double quote payloads
        NIX_BLIND_OS_PAYLOADS.add("\"&" + NIX_BLIND_TEST_CMD + "&\"");
        NIX_BLIND_OS_PAYLOADS.add("\";" + NIX_BLIND_TEST_CMD + ";\"");
        WIN_BLIND_OS_PAYLOADS.add("\"&" + WIN_BLIND_TEST_CMD + "&\"");
        WIN_BLIND_OS_PAYLOADS.add("\"|" + WIN_BLIND_TEST_CMD);
        PS_BLIND_PAYLOADS.add("\";" + PS_BLIND_TEST_CMD);

        // Single quote payloads
        NIX_BLIND_OS_PAYLOADS.add("'&" + NIX_BLIND_TEST_CMD + "&'");
        NIX_BLIND_OS_PAYLOADS.add("';" + NIX_BLIND_TEST_CMD + ";'");
        WIN_BLIND_OS_PAYLOADS.add("'&" + WIN_BLIND_TEST_CMD + "&'");
        WIN_BLIND_OS_PAYLOADS.add("'|" + WIN_BLIND_TEST_CMD);
        PS_BLIND_PAYLOADS.add("';" + PS_BLIND_TEST_CMD);

        // Special payloads
        NIX_BLIND_OS_PAYLOADS.add("\n" + NIX_BLIND_TEST_CMD + "\n"); // force enter
        NIX_BLIND_OS_PAYLOADS.add("`" + NIX_BLIND_TEST_CMD + "`"); // backtick execution
        NIX_BLIND_OS_PAYLOADS.add("||" + NIX_BLIND_TEST_CMD); // or control concatenation
        NIX_BLIND_OS_PAYLOADS.add("&&" + NIX_BLIND_TEST_CMD); // and control concatenation
        NIX_BLIND_OS_PAYLOADS.add("|" + NIX_BLIND_TEST_CMD + "#"); // pipe & comment
        // FoxPro for running os commands
        WIN_BLIND_OS_PAYLOADS.add("run " + WIN_BLIND_TEST_CMD);
        PS_BLIND_PAYLOADS.add(";" + PS_BLIND_TEST_CMD + " #"); // chain & comment

        // uninitialized variable waf bypass
        String insertedCMD = CommandInjectionScanRule.insertUninitVar(NIX_BLIND_TEST_CMD);
        // No quote payloads
        NIX_BLIND_OS_PAYLOADS.add("&" + insertedCMD + "&");
        NIX_BLIND_OS_PAYLOADS.add(";" + insertedCMD + ";");
        // Double quote payloads
        NIX_BLIND_OS_PAYLOADS.add("\"&" + insertedCMD + "&\"");
        NIX_BLIND_OS_PAYLOADS.add("\";" + insertedCMD + ";\"");
        // Single quote payloads
        NIX_BLIND_OS_PAYLOADS.add("'&" + insertedCMD + "&'");
        NIX_BLIND_OS_PAYLOADS.add("';" + insertedCMD + ";'");
        // Special payloads
        NIX_BLIND_OS_PAYLOADS.add("\n" + insertedCMD + "\n");
        NIX_BLIND_OS_PAYLOADS.add("`" + insertedCMD + "`");
        NIX_BLIND_OS_PAYLOADS.add("||" + insertedCMD);
        NIX_BLIND_OS_PAYLOADS.add("&&" + insertedCMD);
        NIX_BLIND_OS_PAYLOADS.add("|" + insertedCMD + "#");
    }

    private static final Logger LOGGER = LogManager.getLogger(CommandInjectionTimingScanRule.class);

    /** The number of seconds used in time-based attacks (i.e. sleep commands). */
    private int timeSleepSeconds = DEFAULT_TIME_SLEEP_SEC;

    @Override
    public int getId() {
        return PLUGIN_ID;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "time.name");
    }

    @Override
    public void init() {
        try {
            timeSleepSeconds = this.getConfig().getInt(RULE_SLEEP_TIME, DEFAULT_TIME_SLEEP_SEC);
        } catch (ConversionException e) {
            LOGGER.debug(
                    "Invalid value for '{}': {}",
                    RULE_SLEEP_TIME,
                    this.getConfig().getString(RULE_SLEEP_TIME));
        }
        LOGGER.debug("Sleep set to {} seconds", timeSleepSeconds);
    }

    /**
     * Gets the number of seconds used in time-based attacks.
     *
     * <p><strong>Note:</strong> Method provided only to ease the unit tests.
     *
     * @return the number of seconds used in time-based attacks.
     */
    int getTimeSleep() {
        return timeSleepSeconds;
    }

    @Override
    public Map<String, String> getAlertTags() {
        return CommandInjectionTimingScanRule.ALERT_TAGS;
    }

    @Override
    public void scan(HttpMessage msg, String paramName, String value) {
        LOGGER.debug(
                "Checking [{}][{}], parameter [{}] for OS Command Injection Vulnerabilities",
                msg.getRequestHeader().getMethod(),
                msg.getRequestHeader().getURI(),
                paramName);

        int blindTargetCount = 0;
        switch (this.getAttackStrength()) {
            case LOW:
                blindTargetCount = 2;
                break;
            case MEDIUM:
                blindTargetCount = 6;
                break;
            case HIGH:
                blindTargetCount = 12;
                break;
            case INSANE:
                blindTargetCount =
                        Math.max(
                                PS_BLIND_PAYLOADS.size(),
                                (Math.max(
                                        NIX_BLIND_OS_PAYLOADS.size(),
                                        WIN_BLIND_OS_PAYLOADS.size())));
                break;
            default:
                // Default to off
        }

        if (inScope(Tech.Linux) || inScope(Tech.MacOS)) {
            if (testCommandInjection(paramName, value, blindTargetCount, NIX_BLIND_OS_PAYLOADS)) {
                return;
            }
        }

        if (isStop()) {
            return;
        }

        if (inScope(Tech.Windows)) {
            // Windows Command Prompt
            if (testCommandInjection(paramName, value, blindTargetCount, WIN_BLIND_OS_PAYLOADS)) {
                return;
            }
            // Check if the user has stopped the scan
            if (isStop()) {
                return;
            }
            // Windows PowerShell
            testCommandInjection(paramName, value, blindTargetCount, PS_BLIND_PAYLOADS);
        }
    }

    /**
     * Tests for injection vulnerabilities with the given payloads.
     *
     * @param paramName the name of the parameter that will be used for testing for injection
     * @param value the value of the parameter that will be used for testing for injection
     * @param blindTargetCount the number of requests for blind payloads
     * @param blindOsPayloads the blind payloads
     * @return {@code true} if the vulnerability was found, {@code false} otherwise.
     */
    private boolean testCommandInjection(
            String paramName, String value, int blindTargetCount, List<String> blindOsPayloads) {

        String paramValue;

        // -----------------------------------------------
        // Check: Time-based Blind OS Command Injection
        // -----------------------------------------------
        // Check for a sleep shell execution by using
        // linear regression to check for a correlation
        // between requested delay and actual delay.
        // -----------------------------------------------

        Iterator<String> it = blindOsPayloads.iterator();

        for (int i = 0; it.hasNext() && (i < blindTargetCount); i++) {
            AtomicReference<HttpMessage> message = new AtomicReference<>();
            String sleepPayload = it.next();
            paramValue = value + sleepPayload.replace("{0}", String.valueOf(timeSleepSeconds));

            TimingUtils.RequestSender requestSender =
                    x -> {
                        HttpMessage msg = getNewMsg();
                        message.set(msg);
                        String finalPayload =
                                value + sleepPayload.replace("{0}", String.valueOf(x));
                        setParameter(msg, paramName, finalPayload);
                        LOGGER.debug("Testing [{}] = [{}]", paramName, finalPayload);

                        sendAndReceive(msg, false);
                        return TimeUnit.MILLISECONDS.toSeconds(msg.getTimeElapsedMillis());
                    };

            boolean isInjectable;
            try {
                try {
                    // use TimingUtils to detect a response to sleep payloads
                    isInjectable =
                            TimingUtils.checkTimingDependence(
                                    BLIND_REQUESTS_LIMIT,
                                    timeSleepSeconds,
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
                    LOGGER.debug(
                            "[Blind OS Command Injection Found] on parameter [{}] with value [{}]",
                            paramName,
                            paramValue);

                    // Attach this alert to the last sent message
                    buildAlert(paramName, paramValue, message.get()).raise();

                    return true;
                }
            } catch (IOException ex) {
                LOGGER.warn(
                        "Blind Command Injection vulnerability check failed for parameter [{}] and payload [{}] due to an I/O error",
                        paramName,
                        paramValue,
                        ex);
            }
            if (isStop()) {
                return false;
            }
        }
        return false;
    }

    AlertBuilder buildAlert(String param, String attack, HttpMessage msg) {
        return buildAlert(param, attack, "", msg)
                .setOtherInfo(
                        Constant.messages.getString(MESSAGE_PREFIX + "time.otherinfo", attack));
    }

    @Override
    public List<Alert> getExampleAlerts() {
        return List.of(buildAlert("qry", "sleep 5", null).build());
    }
}
