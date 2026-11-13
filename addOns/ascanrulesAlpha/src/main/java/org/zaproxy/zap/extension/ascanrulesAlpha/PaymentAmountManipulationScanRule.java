/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.zap.extension.ascanrulesAlpha;

import java.io.IOException;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.sf.json.JSONArray;
import net.sf.json.JSONException;
import net.sf.json.JSONObject;
import net.sf.json.util.JSONUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.addon.commonlib.http.ComparableResponse;

/**
 * Active scan rule which checks whether an API accepts a monetary amount that has been altered to
 * an invalid value, such as a negative or zero amount, instead of rejecting it.
 */
public class PaymentAmountManipulationScanRule extends AbstractAppParamPlugin
        implements CommonActiveScanRuleInfo {

    private static final String MESSAGE_PREFIX = "ascanalpha.paymentamount.";
    private static final Logger LOGGER =
            LogManager.getLogger(PaymentAmountManipulationScanRule.class);

    private static final Set<String> TARGET_METHODS =
            Set.of(
                    HttpRequestHeader.POST,
                    HttpRequestHeader.PUT,
                    HttpRequestHeader.PATCH,
                    HttpRequestHeader.DELETE);

    static final String MONEY_WORDS_CONFIG_KEY = "rules.common.paymentamount.moneywords";

    private static final Set<String> DEFAULT_MONEY_WORDS =
            Set.of(
                    "amount", "amt", "total", "price", "value", "balance", "credit", "debit", "fee",
                    "tip", "refund", "reload", "payment", "charge", "sum", "cost");

    /** Splits parameter names at non-alphanumeric characters and at camelCase boundaries. */
    private static final Pattern NAME_WORD_BOUNDARY =
            Pattern.compile("[^\\p{Alnum}]+|(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])");

    private static final Pattern CURRENCY_OR_SPACE = Pattern.compile("[\\p{Sc}\\s]");
    private static final Pattern JSON_NUMBER = Pattern.compile("-?\\d+(\\.\\d+)?([eE][+-]?\\d+)?");
    private static final Pattern LEADING_PLUS = Pattern.compile("^([\\p{Sc}\\s]*)\\+");
    private static final Pattern EXPONENT = Pattern.compile("[eE]");
    private static final Pattern THOUSANDS_SEPARATED =
            Pattern.compile("\\d{1,3}(,\\d{3})+(\\.\\d+)?");
    private static final Pattern NUMBER_IN_BODY =
            Pattern.compile("(?<![\\w.])-?\\d+(?:\\.\\d+)?(?:[eE][+-]?\\d+)?(?![\\w])");

    private static final List<String> ERROR_KEYS = List.of("error", "errors", "errorMessage");
    private static final List<String> SUCCESS_FLAG_KEYS = List.of("success", "ok");
    private static final Set<String> FAILURE_STATUSES =
            Set.of("error", "fail", "failed", "failure", "invalid", "rejected", "declined");

    private static final String PROBE_MARKER = "__amount_probe__";
    private static final String NON_NUMERIC_CONTROL_VALUE = "notanumber";
    private static final String EXCESS_PRECISION_DIGITS = "001";
    private static final String ZERO_AMOUNT = "0";
    private static final String HUGE_AMOUNT = "999999999999";
    private static final float SIMILARITY_THRESHOLD = 0.80f;

    private static final Map<String, String> ALERT_TAGS;

    private Set<String> moneyWords = DEFAULT_MONEY_WORDS;

    static {
        Map<String, String> alertTags =
                new HashMap<>(
                        CommonAlertTag.toMap(
                                CommonAlertTag.WSTG_V42_BUSL_01_DATA_VALIDATION,
                                CommonAlertTag.OWASP_2025_A06_INSECURE_DESIGN,
                                CommonAlertTag.OWASP_2021_A04_INSECURE_DESIGN));
        alertTags.put(PolicyTag.PENTEST.getTag(), "");
        ALERT_TAGS = Collections.unmodifiableMap(alertTags);
    }

    @Override
    public int getId() {
        return 40049;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(MESSAGE_PREFIX + "desc");
    }

    @Override
    public int getCategory() {
        return Category.MISC;
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
    public int getRisk() {
        return Alert.RISK_MEDIUM;
    }

    @Override
    public int getCweId() {
        return 20; // CWE-20: Improper Input Validation
    }

    @Override
    public int getWascId() {
        return 20; // WASC-20: Improper Input Handling
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    @Override
    public void init() {
        Set<String> words = new HashSet<>();
        for (String word : getConfig().getString(MONEY_WORDS_CONFIG_KEY, "").split(",")) {
            if (!word.isBlank()) {
                words.add(word.strip().toLowerCase(Locale.ROOT));
            }
        }
        moneyWords = words.isEmpty() ? DEFAULT_MONEY_WORDS : Set.copyOf(words);
    }

    @Override
    public void scan() {
        if (!TARGET_METHODS.contains(getBaseMsg().getRequestHeader().getMethod())
                || !isSuccess(getBaseMsg())) {
            return;
        }
        super.scan();
    }

    @Override
    public void scan(HttpMessage msg, String paramName, String paramValue) {
        BigDecimal amount = isMoneyParameter(paramName) ? parseAmount(paramValue) : null;
        if (amount == null) {
            return;
        }

        try {
            ComparableResponse baseline = new ComparableResponse(getBaseMsg(), null);
            Set<BigDecimal> baselineNumbers = numbersIn(getBaseMsg());
            String negatedPayload = negate(paramValue);
            boolean jsonNumber = isJsonNumber(paramName);
            Candidate candidate = null;

            for (String payload : getPayloads(paramValue, amount)) {
                if (isStop()) {
                    return;
                }
                HttpMessage attackMsg = sendWithValue(paramName, payload, jsonNumber);
                if (!isSuccess(attackMsg)) {
                    continue;
                }
                BigDecimal sent = parseAmount(payload);
                if (sent != null
                        && sent.compareTo(amount) != 0
                        && numbersIn(attackMsg).contains(normalise(sent))
                        && !baselineNumbers.contains(normalise(sent))
                        && !isErrorBody(attackMsg.getResponseBody().toString())) {
                    buildAlert(
                                    paramName,
                                    payload,
                                    sent,
                                    payload.equals(negatedPayload) || payload.equals(ZERO_AMOUNT)
                                            ? Alert.CONFIDENCE_MEDIUM
                                            : Alert.CONFIDENCE_LOW,
                                    "otherinfo.reflected",
                                    "-1")
                            .setMessage(attackMsg)
                            .raise();
                    return;
                }
                if (candidate == null
                        && sent != null
                        && sent.compareTo(amount) != 0
                        && isSimilar(attackMsg, baseline)
                        && !isErrorBody(attackMsg.getResponseBody().toString())) {
                    candidate = new Candidate(payload, sent, attackMsg);
                }
            }

            if (candidate == null || isStop()) {
                return;
            }
            HttpMessage controlMsg =
                    sendWithValue(paramName, NON_NUMERIC_CONTROL_VALUE, jsonNumber);
            if (isSuccess(controlMsg) && isSimilar(controlMsg, baseline)) {
                return;
            }
            buildAlert(
                            paramName,
                            candidate.payload(),
                            candidate.amount(),
                            Alert.CONFIDENCE_LOW,
                            "otherinfo.created",
                            "-2")
                    .setMessage(candidate.message())
                    .raise();
        } catch (IOException e) {
            LOGGER.warn(e.getMessage(), e);
        }
    }

    private HttpMessage sendWithValue(String paramName, String value, boolean jsonNumber)
            throws IOException {
        HttpMessage msg = getNewMsg();
        if (jsonNumber && JSON_NUMBER.matcher(value).matches()) {
            // The JSON variant quotes the injected value of a number, so set it as is.
            setEscapedParameter(msg, paramName, value);
        } else {
            setParameter(msg, paramName, value);
        }
        sendAndReceive(msg);
        return msg;
    }

    /**
     * Tells whether the parameter is an unquoted JSON number in the original request, by checking
     * if the variant leaves a quote before the injected value, which it does for strings only.
     */
    private boolean isJsonNumber(String paramName) {
        if (!getBaseMsg().getRequestHeader().hasContentType("json")) {
            return false;
        }
        String body = setEscapedParameter(getNewMsg(), paramName, PROBE_MARKER);
        int index = body == null ? -1 : body.indexOf(PROBE_MARKER);
        return index > 0 && body.charAt(index - 1) != '"';
    }

    private static String negate(String value) {
        return "-" + LEADING_PLUS.matcher(value).replaceFirst("$1");
    }

    private boolean isSimilar(HttpMessage msg, ComparableResponse baseline) {
        return new ComparableResponse(msg, null).compareWith(baseline) >= SIMILARITY_THRESHOLD;
    }

    private AlertBuilder buildAlert(
            String param,
            String payload,
            BigDecimal amount,
            int confidence,
            String otherInfoKey,
            String alertRefSuffix) {
        return newAlert()
                .setRisk(amount != null && amount.signum() < 0 ? Alert.RISK_HIGH : getRisk())
                .setConfidence(confidence)
                .setParam(param)
                .setAttack(payload)
                .setEvidence(payload)
                .setOtherInfo(
                        Constant.messages.getString(MESSAGE_PREFIX + otherInfoKey, payload, param))
                .setAlertRef(getId() + alertRefSuffix);
    }

    private List<String> getPayloads(String value, BigDecimal amount) {
        List<String> payloads = new ArrayList<>();
        if (amount.signum() > 0) {
            payloads.add(negate(value));
        }
        if (amount.signum() != 0) {
            payloads.add(ZERO_AMOUNT);
        }
        if (isAtLeast(AttackStrength.MEDIUM)) {
            if (!EXPONENT.matcher(value).find()) {
                payloads.add(withExcessPrecision(value));
            }
            payloads.add(HUGE_AMOUNT);
        }
        payloads.removeIf(
                payload -> {
                    BigDecimal sent = parseAmount(payload);
                    return sent != null && sent.compareTo(amount) == 0;
                });
        return payloads;
    }

    private boolean isAtLeast(AttackStrength strength) {
        return getAttackStrength().compareTo(strength) >= 0;
    }

    private static String withExcessPrecision(String value) {
        int i = value.length();
        while (i > 0 && !Character.isDigit(value.charAt(i - 1))) {
            i--;
        }
        String number = value.substring(0, i);
        String rest = value.substring(i);
        if (number.contains(".")) {
            return number + EXCESS_PRECISION_DIGITS + rest;
        }
        if (rest.startsWith(".")) {
            return number + "." + EXCESS_PRECISION_DIGITS + rest.substring(1);
        }
        return number + "." + EXCESS_PRECISION_DIGITS + rest;
    }

    boolean isMoneyParameter(String name) {
        if (name == null) {
            return false;
        }
        for (String word : NAME_WORD_BOUNDARY.split(name)) {
            if (moneyWords.contains(word.toLowerCase(Locale.ROOT))) {
                return true;
            }
        }
        return false;
    }

    /**
     * Parses the given value as a decimal, ignoring currency symbols, whitespace and comma
     * thousands separators.
     *
     * @return the parsed amount, or {@code null} if the value is not a decimal.
     */
    static BigDecimal parseAmount(String value) {
        if (value == null) {
            return null;
        }
        String cleaned = CURRENCY_OR_SPACE.matcher(value).replaceAll("");
        if (THOUSANDS_SEPARATED.matcher(cleaned.replaceFirst("^[+-]", "")).matches()) {
            cleaned = cleaned.replace(",", "");
        }
        try {
            return new BigDecimal(cleaned);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    /**
     * Tells whether the body is a JSON object which declares a failure at its top level, using an
     * error key with a value, a false success flag or a failure status.
     */
    static boolean isErrorBody(String body) {
        JSONObject json;
        try {
            json = JSONObject.fromObject(body);
        } catch (JSONException e) {
            return false;
        }
        if (json.isNullObject()) {
            return false;
        }
        return ERROR_KEYS.stream().anyMatch(key -> hasErrorValue(json, key))
                || SUCCESS_FLAG_KEYS.stream()
                        .anyMatch(key -> json.has(key) && Boolean.FALSE.equals(json.get(key)))
                || (json.get("status") instanceof String status
                        && FAILURE_STATUSES.contains(status.strip().toLowerCase(Locale.ROOT)));
    }

    private static boolean hasErrorValue(JSONObject json, String key) {
        if (!json.has(key)) {
            return false;
        }
        Object value = json.get(key);
        return !(JSONUtils.isNull(value)
                || Boolean.FALSE.equals(value)
                || (value instanceof String text && text.isBlank())
                || (value instanceof JSONArray array && array.isEmpty()));
    }

    private static Set<BigDecimal> numbersIn(HttpMessage msg) {
        Set<BigDecimal> numbers = new HashSet<>();
        Matcher matcher = NUMBER_IN_BODY.matcher(msg.getResponseBody().toString());
        while (matcher.find()) {
            try {
                numbers.add(normalise(new BigDecimal(matcher.group())));
            } catch (NumberFormatException e) {
                LOGGER.debug("Ignoring unparseable number: {}", matcher.group());
            }
        }
        return numbers;
    }

    private static BigDecimal normalise(BigDecimal number) {
        return number.signum() == 0 ? BigDecimal.ZERO : number.stripTrailingZeros();
    }

    @Override
    public List<Alert> getExampleAlerts() {
        return List.of(
                buildAlert(
                                "amount",
                                "-10.00",
                                new BigDecimal("-10.00"),
                                Alert.CONFIDENCE_MEDIUM,
                                "otherinfo.reflected",
                                "-1")
                        .build(),
                buildAlert(
                                "amount",
                                "0",
                                BigDecimal.ZERO,
                                Alert.CONFIDENCE_LOW,
                                "otherinfo.created",
                                "-2")
                        .build());
    }

    private record Candidate(String payload, BigDecimal amount, HttpMessage message) {}
}
