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
package org.zaproxy.addon.authhelper.internal;

import com.bastiaanjansen.otp.HMACAlgorithm;
import com.bastiaanjansen.otp.TOTPGenerator;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openqa.selenium.By;
import org.openqa.selenium.Keys;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.commonlib.internal.TotpSupport;
import org.zaproxy.zap.authentication.UsernamePasswordAuthenticationCredentials;
import org.zaproxy.zap.utils.EnableableInterface;
import org.zaproxy.zap.utils.Orderable;

/**
 * An authentication step in BBA.
 *
 * <p>For example, clicking a menu to access the login form, or fill a custom field.
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class AuthenticationStep
        implements EnableableInterface, Orderable, Comparable<AuthenticationStep> {

    /**
     * The result of validating a new {@link AuthenticationStep}.
     *
     * @see AuthenticationStep#validate(AuthenticationStep, AuthenticationStep, List)
     */
    public enum ValidationResult {

        /** The {@code description} duplicates an existing step. */
        DUPLICATED,

        /** The {@code description} is empty. */
        EMPTY_DESCRIPTION,

        /** The {@code cssSelector} or {@code xpath} is required but not set. */
        NO_CSS_OR_XPATH,

        /** The {@code secret} for TOTP is missing. */
        NO_TOTP_SECRET,

        /** The {@code type} is not set. */
        NO_TYPE,

        /** The {@code value} is required but not set. */
        NO_VALUE,

        /** The {@code timeout} is not a valid milliseconds duration. */
        INVALID_TIMEOUT,

        /** TOTP period is invalid. */
        INVALID_TOTP_PERIOD,

        /** TOTP digits is invalid. */
        INVALID_TOTP_DIGITS,

        /** TOTP algorithm is invalid. */
        INVALID_TOTP_ALGORITHM,

        /** The {@code AuthenticationStep} is valid. */
        VALID,
    }

    public enum Type {
        AUTO_STEPS,
        CLICK,
        CUSTOM_FIELD,
        ESCAPE,
        PASSWORD,
        RETURN,
        TOTP_FIELD,
        USERNAME;

        @Override
        public String toString() {
            return Constant.messages.getString(
                    "authhelper.auth.method.browser.steps.ui.type."
                            + name().toLowerCase(Locale.ROOT));
        }
    }

    private static final Logger LOGGER = LogManager.getLogger(AuthenticationStep.class);

    private static final String DATA_FIELD_SEPARATOR = ";";

    private String description;

    private Type type;

    private String cssSelector;
    private String xpath;

    private String value;
    private int timeout = 1000;

    private String totpSecret;
    private int totpPeriod = 30;
    private int totpDigits = 6;

    @SuppressWarnings("deprecation")
    private String totpAlgorithm = HMACAlgorithm.SHA1.name();

    private boolean enabled;
    private int order;

    public AuthenticationStep(AuthenticationStep other) {
        description = other.description;
        type = other.type;
        cssSelector = other.cssSelector;
        xpath = other.xpath;
        value = other.value;
        timeout = other.timeout;
        enabled = other.enabled;
        order = other.order;

        totpSecret = other.totpSecret;
        totpPeriod = other.totpPeriod;
        totpDigits = other.totpDigits;
        totpAlgorithm = other.totpAlgorithm;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    @Override
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    @Override
    public int getOrder() {
        return order;
    }

    @Override
    public void setOrder(int order) {
        this.order = order;
    }

    public WebElement execute(WebDriver wd, UsernamePasswordAuthenticationCredentials credentials) {
        By by = createtBy();

        WebElement element =
                new WebDriverWait(wd, Duration.ofMillis(timeout))
                        .until(ExpectedConditions.presenceOfElementLocated(by));

        switch (getType()) {
            case CLICK:
                element.click();
                break;

            case CUSTOM_FIELD:
                element.sendKeys(value);
                break;

            case ESCAPE:
                element.sendKeys(Keys.ESCAPE);
                break;

            case PASSWORD:
                element.sendKeys(credentials.getPassword());
                break;

            case RETURN:
                element.sendKeys(Keys.RETURN);
                break;

            case TOTP_FIELD:
                element.sendKeys(getTotpCode(credentials));
                break;

            case USERNAME:
                element.sendKeys(credentials.getUsername());
                break;

            default:
                break;
        }

        return element;
    }

    private CharSequence getTotpCode(UsernamePasswordAuthenticationCredentials credentials) {
        CharSequence code = TotpSupport.getCode(credentials);
        if (code != null) {
            return code;
        }

        // Fallback to data from the step for now.
        return new TOTPGenerator.Builder(totpSecret)
                .withHOTPGenerator(
                        builder ->
                                builder.withAlgorithm(HMACAlgorithm.valueOf(totpAlgorithm))
                                        .withPasswordLength(totpDigits))
                .withPeriod(Duration.ofSeconds(totpPeriod))
                .build()
                .now();
    }

    private By createtBy() {
        if (StringUtils.isNotEmpty(cssSelector)) {
            return By.cssSelector(cssSelector);
        }

        return By.xpath(xpath);
    }

    @Override
    public int compareTo(AuthenticationStep o) {
        return Integer.compare(order, o.order);
    }

    /**
     * Validates the {@code newStep}.
     *
     * @param oldStep the step prior the changes, if any.
     * @param newStep the new step.
     * @param steps the existing steps.
     * @return the result of the validation.
     */
    public static ValidationResult validate(
            AuthenticationStep oldStep,
            AuthenticationStep newStep,
            List<? extends AuthenticationStep> steps) {
        if (isEmpty(newStep.getDescription())) {
            return ValidationResult.EMPTY_DESCRIPTION;
        }

        if (newStep.getType() == null) {
            return ValidationResult.NO_TYPE;
        }

        if (newStep.getType() != Type.AUTO_STEPS) {
            if (isEmpty(newStep.getCssSelector()) && isEmpty(newStep.getXpath())) {
                return ValidationResult.NO_CSS_OR_XPATH;
            }

            try {
                int value = Integer.valueOf(newStep.getTimeout());
                if (value <= 0) {
                    return ValidationResult.INVALID_TIMEOUT;
                }
            } catch (Exception e) {
                return ValidationResult.INVALID_TIMEOUT;
            }
        }

        if (newStep.getType() == Type.CUSTOM_FIELD && isEmpty(newStep.getValue())) {
            return ValidationResult.NO_VALUE;
        } else if (newStep.getType() == Type.TOTP_FIELD) {

            if (isEmpty(newStep.getTotpSecret())) {
                return ValidationResult.NO_TOTP_SECRET;
            }

            if (newStep.getTotpPeriod() <= 0) {
                return ValidationResult.INVALID_TOTP_PERIOD;
            }

            if (newStep.getTotpDigits() <= 0) {
                return ValidationResult.INVALID_TOTP_DIGITS;
            }

            try {
                HMACAlgorithm.valueOf(newStep.getTotpAlgorithm());
            } catch (Exception e) {
                return ValidationResult.INVALID_TOTP_ALGORITHM;
            }
        }

        if (oldStep == null
                || !Objects.equals(oldStep.getDescription(), newStep.getDescription())) {
            String description = newStep.getDescription();
            for (var step : steps) {
                if (description.equals(step.getDescription())) {
                    return ValidationResult.DUPLICATED;
                }
            }
        }

        return ValidationResult.VALID;
    }

    public static AuthenticationStep decode(String data) {
        String[] pieces = data.split(DATA_FIELD_SEPARATOR, -1);
        AuthenticationStep step = null;
        int field = 0;
        try {
            step = new AuthenticationStep();
            step.setEnabled(Boolean.parseBoolean(pieces[field]));
            field++;
            step.setOrder(Integer.parseInt(pieces[field]));
            field++;
            step.setDescription(base64Decode(pieces[field]));
            field++;
            step.setType(AuthenticationStep.Type.valueOf(base64Decode(pieces[field])));
            field++;
            step.setCssSelector(base64Decode(pieces[field]));
            field++;
            step.setXpath(base64Decode(pieces[field]));
            field++;
            step.setValue(base64Decode(pieces[field]));
            field++;
            step.setTimeout(Integer.parseInt(pieces[field]));
            field++;
            step.setTotpSecret(base64Decode(pieces[field]));
            field++;
            step.setTotpPeriod(Integer.parseInt(pieces[field]));
            field++;
            step.setTotpDigits(Integer.parseInt(pieces[field]));
            field++;
            step.setTotpAlgorithm(base64Decode(pieces[field]));
        } catch (Exception e) {
            LOGGER.error("An error occurred while decoding: {}", data, e);
        }
        return step;
    }

    public static String encode(AuthenticationStep step) {
        return new StringBuilder(100)
                .append(step.isEnabled())
                .append(DATA_FIELD_SEPARATOR)
                .append(step.getOrder())
                .append(DATA_FIELD_SEPARATOR)
                .append(base64Encode(step.getDescription()))
                .append(DATA_FIELD_SEPARATOR)
                .append(base64Encode(step.getType().name()))
                .append(DATA_FIELD_SEPARATOR)
                .append(base64Encode(step.getCssSelector()))
                .append(DATA_FIELD_SEPARATOR)
                .append(base64Encode(step.getXpath()))
                .append(DATA_FIELD_SEPARATOR)
                .append(base64Encode(step.getValue()))
                .append(DATA_FIELD_SEPARATOR)
                .append(step.getTimeout())
                .append(DATA_FIELD_SEPARATOR)
                .append(base64Encode(step.getTotpSecret()))
                .append(DATA_FIELD_SEPARATOR)
                .append(step.getTotpPeriod())
                .append(DATA_FIELD_SEPARATOR)
                .append(step.getTotpDigits())
                .append(DATA_FIELD_SEPARATOR)
                .append(base64Encode(step.getTotpAlgorithm()))
                .append(DATA_FIELD_SEPARATOR)
                .toString();
    }

    public Map<String, Object> toMap() {
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("description", getDescription());
        data.put("type", getType().name());
        data.put("cssSelector", getCssSelector());
        data.put("xpath", getXpath());
        data.put("value", getValue());
        data.put("timeout", getTimeout());

        if (!isEmpty(getTotpSecret())) {
            Map<String, Object> totpData = new LinkedHashMap<>();
            totpData.put("secret", getTotpSecret());
            totpData.put("period", getTotpPeriod());
            totpData.put("digits", getTotpDigits());
            totpData.put("algorithm", getTotpAlgorithm());
            data.put("totp", totpData);
        }

        return data;
    }

    @SuppressWarnings("rawtypes")
    public static AuthenticationStep fromMap(Map<String, Object> data) {
        AuthenticationStep step = new AuthenticationStep();
        step.setEnabled(true);
        step.setDescription(toString(data.get("description")));
        step.setType(AuthenticationStep.Type.valueOf(toString(data.get("type"))));
        step.setCssSelector(toString(data.get("cssSelector")));
        step.setXpath(toString(data.get("xpath")));
        step.setValue(toString(data.get("value")));
        step.setTimeout(Integer.valueOf(toString(data.get("timeout"), "1000")));

        Object e = data.get("totp");
        if (e instanceof Map totp) {
            step.setTotpSecret(toString(totp.get("secret")));
            step.setTotpPeriod(Integer.valueOf(toString(totp.get("period"))));
            step.setTotpDigits(Integer.valueOf(toString(totp.get("digits"))));
            step.setTotpAlgorithm(toString(totp.get("algorithm")));
        }
        return step;
    }

    private static String toString(Object source) {
        return toString(source, null);
    }

    private static String toString(Object source, String fallback) {
        return source == null ? fallback : source.toString();
    }

    private static boolean isEmpty(String string) {
        return string == null || string.isBlank();
    }

    private static String base64Decode(String data) {
        if (data.isEmpty()) {
            return null;
        }
        return new String(Base64.getDecoder().decode(data), StandardCharsets.UTF_8);
    }

    private static String base64Encode(String data) {
        if (data == null) {
            return "";
        }
        return Base64.getEncoder().encodeToString(data.getBytes(StandardCharsets.UTF_8));
    }
}
