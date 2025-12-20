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
package org.zaproxy.addon.authhelper.internal.auth;

import java.time.Duration;
import java.util.LinkedList;
import java.util.List;
import java.util.Queue;
import org.apache.commons.lang3.Strings;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openqa.selenium.By;
import org.openqa.selenium.TimeoutException;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.ExpectedCondition;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.authhelper.AuthUtils;
import org.zaproxy.addon.authhelper.AuthenticationDiagnostics;
import org.zaproxy.addon.authhelper.internal.AuthenticationStep;
import org.zaproxy.addon.commonlib.internal.TotpSupport;
import org.zaproxy.zap.authentication.UsernamePasswordAuthenticationCredentials;
import org.zaproxy.zap.model.Context;

public final class MsLoginAuthenticator implements Authenticator {

    private static final String PARTIAL_LOGIN_URL = "login.microsoftonline";

    private static final String LOGIN_URL = "https://" + PARTIAL_LOGIN_URL;

    private static final Logger LOGGER = LogManager.getLogger(MsLoginAuthenticator.class);

    private static final Duration PAGE_LOAD_WAIT_UNTIL = Duration.ofSeconds(5);
    private static final Duration DEFAULT_WAIT_UNTIL = Duration.ofSeconds(10);

    private static final By USERNAME_FIELD = By.id("i0116");
    private static final By PASSWORD_FIELD = By.id("i0118");
    private static final By SUBMIT_BUTTON = By.id("idSIButton9");
    private static final By KMSI_FIELD = By.id("KmsiCheckboxField");
    private static final By PROOF_REDIRECT_FIELD = By.id("idSubmit_ProofUp_Redirect");
    private static final By PROOF_TOTP_FIELD = By.id("idTxtBx_SAOTCC_OTC");
    private static final By PROOF_TOTP_VERIFY_FIELD = By.id("idSubmit_SAOTCC_Continue");
    private static final By PROOF_DONE_FIELD = By.id("id__5");

    private enum State {
        START,

        ACCOUNT_SELECTION,

        USERNAME,
        PASSWORD,
        SUBMIT,

        POST_PASSWORD,
        STAY_SIGNED_IN,

        PROOF_REDIRECT,
        PROOF_TOTP,
        PROOF,
    }

    @Override
    public boolean isOwnSite(HttpMessage msg) {
        return msg.getRequestHeader().getURI().toString().startsWith(LOGIN_URL);
    }

    @Override
    public Result authenticate(
            AuthenticationDiagnostics diags,
            WebDriver wd,
            Context context,
            String loginPageUrl,
            UsernamePasswordAuthenticationCredentials credentials,
            int stepDelayInSecs,
            int waitInSecs,
            List<AuthenticationStep> steps) {
        return authenticateImpl(diags, wd, credentials, stepDelayInSecs);
    }

    private Result authenticateImpl(
            AuthenticationDiagnostics diags,
            WebDriver wd,
            UsernamePasswordAuthenticationCredentials credentials,
            int stepDelayInSecs) {

        if (!isMsLoginFlow(wd, PAGE_LOAD_WAIT_UNTIL)) {
            LOGGER.debug("Expected login URL not present, skipping login.");
            return Authenticator.NO_AUTH;
        }

        Queue<State> states = new LinkedList<>();
        states.add(State.START);

        boolean successful = false;
        boolean userField = false;
        boolean pwdField = false;
        int totpRetries = 0;

        do {
            switch (states.remove()) {
                case START:
                    try {
                        waitForElement(wd, USERNAME_FIELD);
                        userField = true;
                        states.add(State.USERNAME);
                        break;

                    } catch (TimeoutException e) {
                        // Try next state.
                    }

                    if (findElement(wd, By.tagName("div"), "Pick an account") != null) {
                        states.add(State.ACCOUNT_SELECTION);
                    } else if (findElement(wd, PROOF_TOTP_FIELD) != null) {
                        userField = true;
                        pwdField = true;
                        states.add(State.PROOF_TOTP);
                    } else {
                        diags.recordStep(
                                wd,
                                Constant.messages.getString(
                                        "authhelper.auth.method.diags.steps.ms.missingusername"));
                        LOGGER.debug("Unexpected initial state, failing login.");
                    }

                    break;

                case ACCOUNT_SELECTION:
                    WebElement userElement =
                            findElement(wd, By.tagName("div"), credentials.getUsername());
                    if (userElement != null) {
                        userField = true;

                        if (isUserLoggedIn(wd, userElement)) {
                            pwdField = true;
                            states.add(State.POST_PASSWORD);
                        } else {
                            states.add(State.PASSWORD);
                        }

                        diags.recordStep(
                                wd,
                                Constant.messages.getString(
                                        "authhelper.auth.method.diags.steps.ms.clickaccount"),
                                userElement);
                        userElement.click();
                        break;
                    }

                    WebElement otherAccountElement =
                            findElement(wd, By.tagName("div"), "Use another account");
                    if (otherAccountElement != null) {
                        diags.recordStep(
                                wd,
                                Constant.messages.getString(
                                        "authhelper.auth.method.diags.steps.ms.clickaccountother"),
                                otherAccountElement);
                        otherAccountElement.click();
                        states.add(State.START);
                        break;
                    }

                    diags.recordStep(
                            wd,
                            Constant.messages.getString(
                                    "authhelper.auth.method.diags.steps.ms.stepunknown"));
                    LOGGER.debug(
                            "Still in pick an account but no known state, assuming unsuccessful login.");

                    break;

                case USERNAME:
                    AuthUtils.fillUserName(
                            diags,
                            wd,
                            credentials.getUsername(),
                            wd.findElement(USERNAME_FIELD),
                            stepDelayInSecs);

                    states.add(State.SUBMIT);
                    states.add(State.PASSWORD);
                    break;

                case PASSWORD:
                    try {
                        AuthUtils.fillPassword(
                                diags,
                                wd,
                                credentials.getPassword(),
                                waitForElement(wd, PASSWORD_FIELD),
                                stepDelayInSecs);
                        pwdField = true;
                    } catch (TimeoutException e) {
                        diags.recordStep(
                                wd,
                                Constant.messages.getString(
                                        "authhelper.auth.method.diags.steps.ms.missingpassword"));
                        LOGGER.debug("Expected password field not found, ending login.");
                        break;
                    }

                    states.add(State.SUBMIT);
                    states.add(State.POST_PASSWORD);
                    break;

                case SUBMIT:
                    try {
                        WebElement submitElement = waitForElement(wd, SUBMIT_BUTTON);
                        diags.recordStep(
                                wd,
                                Constant.messages.getString(
                                        "authhelper.auth.method.diags.steps.ms.clickbutton"),
                                submitElement);
                        submitElement.click();
                    } catch (TimeoutException e) {
                        diags.recordStep(
                                wd,
                                Constant.messages.getString(
                                        "authhelper.auth.method.diags.steps.ms.missingbutton"));
                        LOGGER.debug("Expected button not found, ending login.");
                        break;
                    }
                    break;

                case POST_PASSWORD:
                    if (!isMsLoginFlow(wd)) {
                        LOGGER.debug(
                                "URL no longer login after successfully completing all steps.");

                        successful = true;
                        break;
                    }
                    diags.recordStep(
                            wd,
                            Constant.messages.getString(
                                    "authhelper.auth.method.diags.steps.ms.stepchoice"));

                    try {
                        waitForElement(wd, PROOF_REDIRECT_FIELD);
                        states.add(State.PROOF_REDIRECT);
                        break;
                    } catch (TimeoutException e) {
                        // Ignore, there's still the next step to check.
                    }

                    try {
                        WebElement proofTotpElement =
                                waitForElement(
                                        wd,
                                        new ElemenContainsText(
                                                By.id("idDiv_SAOTCC_Description"),
                                                "authenticator"));
                        if (proofTotpElement != null) {
                            states.add(State.PROOF_TOTP);
                            break;
                        }
                    } catch (TimeoutException e) {
                        // Ignore, there's still the next step to check.
                    }

                    try {
                        waitForElement(wd, KMSI_FIELD);
                        states.add(State.STAY_SIGNED_IN);
                        break;
                    } catch (TimeoutException e) {
                        diags.recordStep(
                                wd,
                                Constant.messages.getString(
                                        "authhelper.auth.method.diags.steps.ms.stepunknown"));
                        LOGGER.debug(
                                "Still in login URL but no keep me signed in field found, assuming unsuccessful login.");
                    }

                    break;

                case STAY_SIGNED_IN:
                    WebElement kmsiElement = wd.findElement(KMSI_FIELD);
                    kmsiElement.click();
                    diags.recordStep(
                            wd,
                            Constant.messages.getString(
                                    "authhelper.auth.method.diags.steps.ms.clickkmsi"),
                            kmsiElement);

                    states.add(State.SUBMIT);
                    states.add(State.POST_PASSWORD);
                    break;

                case PROOF_REDIRECT:
                    WebElement proofElement = wd.findElement(PROOF_REDIRECT_FIELD);
                    proofElement.click();
                    diags.recordStep(
                            wd,
                            Constant.messages.getString(
                                    "authhelper.auth.method.diags.steps.ms.clickproofredirect"),
                            proofElement);

                    states.add(State.PROOF);
                    break;

                case PROOF_TOTP:
                    totpRetries++;

                    if (totpRetries > 2) {
                        diags.recordStep(
                                wd,
                                Constant.messages.getString(
                                        "authhelper.auth.method.diags.steps.ms.clickprooftotperror"));
                        LOGGER.debug("TOTP proof failed, assuming unsuccessful login.");
                        break;
                    }

                    WebElement proofTotpElement = wd.findElement(PROOF_TOTP_FIELD);
                    WebElement proofTotpVerifyElement = wd.findElement(PROOF_TOTP_VERIFY_FIELD);
                    proofTotpElement.clear();
                    proofTotpElement.sendKeys(TotpSupport.getCode(credentials));
                    proofTotpVerifyElement.click();
                    diags.recordStep(
                            wd,
                            Constant.messages.getString(
                                    "authhelper.auth.method.diags.steps.ms.clickprooftotpverify"),
                            proofTotpVerifyElement);

                    if (findElementContains(wd, By.id("idDiv_SAOTCC_ErrorMsg_OTC"), "try again")
                            != null) {
                        states.add(State.PROOF_TOTP);
                    } else {
                        states.add(State.POST_PASSWORD);
                    }

                    break;

                case PROOF:
                    try {
                        waitForElement(wd, new ElementWithText(By.tagName("button"), "Skip setup"));
                        WebElement doneElement =
                                waitForElement(wd, new ElementWithText(PROOF_DONE_FIELD, "Done"));
                        doneElement.click();
                        diags.recordStep(
                                wd,
                                Constant.messages.getString(
                                        "authhelper.auth.method.diags.steps.ms.clickproofdone"),
                                doneElement);

                        states.add(State.POST_PASSWORD);
                        break;
                    } catch (TimeoutException e) {
                        diags.recordStep(
                                wd,
                                Constant.messages.getString(
                                        "authhelper.auth.method.diags.steps.ms.stepproofunknown"));
                        LOGGER.debug(
                                "Still in proof but no skip/done button found, assuming unsuccessful login.");
                        break;
                    }
            }
        } while (!states.isEmpty());

        return new Result(true, successful, userField, pwdField);
    }

    private static boolean isUserLoggedIn(WebDriver wd, WebElement userElement) {
        return userElement.findElement(By.xpath("..")).findElements(By.tagName("div")).stream()
                .anyMatch(e -> "Signed in".equalsIgnoreCase(e.getText()));
    }

    private static WebElement findElement(WebDriver wd, By by) {
        return wd.findElements(by).stream().findFirst().orElse(null);
    }

    private static WebElement findElementContains(WebDriver wd, By by, String text) {
        return wd.findElements(by).stream()
                .filter(e -> Strings.CI.contains(e.getText(), text))
                .findFirst()
                .orElse(null);
    }

    private static WebElement findElement(WebDriver wd, By by, String text) {
        return wd.findElements(by).stream()
                .filter(e -> text.equalsIgnoreCase(e.getText()))
                .findFirst()
                .orElse(null);
    }

    private WebElement waitForElement(WebDriver wd, By by) {
        return waitForElement(wd, ExpectedConditions.elementToBeClickable(by));
    }

    private WebElement waitForElement(WebDriver wd, ExpectedCondition<WebElement> condition) {
        return new WebDriverWait(wd, DEFAULT_WAIT_UNTIL).until(condition);
    }

    private static boolean isMsLoginFlow(WebDriver wd) {
        return isMsLoginFlow(wd, DEFAULT_WAIT_UNTIL);
    }

    private static boolean isMsLoginFlow(WebDriver wd, Duration duration) {
        try {
            new WebDriverWait(wd, duration)
                    .until(ExpectedConditions.urlContains(PARTIAL_LOGIN_URL));
            return true;
        } catch (TimeoutException e) {
            return false;
        }
    }

    private static class ElementWithText implements ExpectedCondition<WebElement> {

        private final By locator;
        private final String text;

        ElementWithText(By locator, String text) {
            this.locator = locator;
            this.text = text;
        }

        @Override
        public WebElement apply(WebDriver driver) {
            return driver.findElements(locator).stream()
                    .filter(e -> text.equalsIgnoreCase(e.getText()))
                    .findFirst()
                    .orElse(null);
        }

        @Override
        public String toString() {
            return String.format("element '%s' with text '%s' is not present", locator, text);
        }
    }

    private static class ElemenContainsText implements ExpectedCondition<WebElement> {

        private final By locator;
        private final String text;

        ElemenContainsText(By locator, String text) {
            this.locator = locator;
            this.text = text;
        }

        @Override
        public WebElement apply(WebDriver driver) {
            return driver.findElements(locator).stream()
                    .filter(e -> Strings.CI.contains(e.getText(), text))
                    .findFirst()
                    .orElse(null);
        }

        @Override
        public String toString() {
            return String.format("element '%s' containing text '%s' is not present", locator, text);
        }
    }
}
