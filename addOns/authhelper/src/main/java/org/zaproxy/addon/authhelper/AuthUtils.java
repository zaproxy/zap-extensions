/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.addon.authhelper;

import java.net.HttpCookie;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import lombok.Setter;
import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.Source;
import net.sf.json.JSONArray;
import net.sf.json.JSONException;
import net.sf.json.JSONObject;
import net.sf.json.util.JSONUtils;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.Strings;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openqa.selenium.By;
import org.openqa.selenium.JavascriptExecutor;
import org.openqa.selenium.Keys;
import org.openqa.selenium.NoSuchShadowRootException;
import org.openqa.selenium.StaleElementReferenceException;
import org.openqa.selenium.TimeoutException;
import org.openqa.selenium.UsernameAndPassword;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebDriverException;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.firefox.FirefoxDriver;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpHeaderField;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.parosproxy.paros.network.HttpStatusCode;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.authhelper.BrowserBasedAuthenticationMethodType.BrowserBasedAuthenticationMethod;
import org.zaproxy.addon.authhelper.internal.AuthenticationStep;
import org.zaproxy.addon.authhelper.internal.auth.Authenticator;
import org.zaproxy.addon.authhelper.internal.auth.DefaultAuthenticator;
import org.zaproxy.addon.authhelper.internal.auth.MsLoginAuthenticator;
import org.zaproxy.addon.commonlib.ResourceIdentificationUtils;
import org.zaproxy.addon.network.NetworkUtils;
import org.zaproxy.zap.authentication.AuthenticationCredentials;
import org.zaproxy.zap.authentication.AuthenticationMethod;
import org.zaproxy.zap.authentication.AuthenticationMethod.AuthCheckingStrategy;
import org.zaproxy.zap.authentication.AuthenticationMethod.UnsupportedAuthenticationCredentialsException;
import org.zaproxy.zap.authentication.UsernamePasswordAuthenticationCredentials;
import org.zaproxy.zap.extension.selenium.BrowserHook;
import org.zaproxy.zap.extension.selenium.ExtensionSelenium;
import org.zaproxy.zap.extension.selenium.SeleniumScriptUtils;
import org.zaproxy.zap.extension.users.ExtensionUserManagement;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.model.SessionStructure;
import org.zaproxy.zap.network.HttpRedirectionValidator;
import org.zaproxy.zap.network.HttpRequestConfig;
import org.zaproxy.zap.users.User;
import org.zaproxy.zap.utils.Pair;
import org.zaproxy.zap.utils.Stats;
import org.zaproxy.zest.core.v1.ZestClientElement;
import org.zaproxy.zest.core.v1.ZestScript;
import org.zaproxy.zest.core.v1.ZestStatement;

public class AuthUtils {

    public static final String AUTH_NO_USER_FIELD_STATS = "stats.auth.browser.nouserfield";
    public static final String AUTH_NO_PASSWORD_FIELD_STATS = "stats.auth.browser.nopasswordfield";
    public static final String AUTH_FOUND_FIELDS_STATS = "stats.auth.browser.foundfields";
    public static final String AUTH_SESSION_TOKEN_STATS_PREFIX = "stats.auth.sessiontoken.";
    public static final String AUTH_SESSION_TOKENS_MAX = "stats.auth.sessiontokens.max";
    public static final String AUTH_BROWSER_PASSED_STATS = "stats.auth.browser.passed";
    public static final String AUTH_BROWSER_FAILED_STATS = "stats.auth.browser.failed";
    public static final String AUTH_BROWSER_HTTP_AUTH_BASIC_STATS = "stats.auth.browser.http.basic";
    public static final String AUTH_BROWSER_HTTP_AUTH_DIGEST_STATS =
            "stats.auth.browser.http.digest";
    public static final String AUTH_BROWSER_HTTP_AUTH_ERROR_STATS = "stats.auth.browser.http.error";
    public static final String AUTH_BROWSER_HTTP_AUTH_PASSED_STATS =
            "stats.auth.browser.http.passed";
    public static final String AUTH_BROWSER_HTTP_AUTH_FAILED_STATS =
            "stats.auth.browser.http.failed";
    public static final String AUTH_BROWSER_HTTP_AUTH_NOT_SUPPORTED_STATS =
            "stats.auth.browser.http.notsupported";
    public static final String AUTH_BROWSER_HTTP_AUTH_UNKNOWN_STATS =
            "stats.auth.browser.http.unknown";

    public static final String[] HEADERS = {HttpHeader.AUTHORIZATION, "X-CSRF-Token"};
    public static final String[] JSON_IDS = {"accesstoken", "token"};
    private static final List<String> USERNAME_FIELD_INDICATORS =
            List.of("email", "signinname", "uname", "user", "name", "nome", "nombre");
    /* A selection of the most common login label links - just European languages for now - more suggestions appreciated */
    protected static List<String> LOGIN_LABELS_P1 =
            List.of(
                    "login",
                    "log in",
                    "log-in",
                    "signin",
                    "sign in",
                    "sign-in",
                    "iniciar sesión", // Spanish: login
                    "ingresar", // Ditto.
                    "acceder", // Spanish: sign in
                    "connexion", // French: login
                    "se connecter", // French: sign in
                    "anmeldung", // German: login
                    "einloggen", // German: sign in
                    "accesso", // Italian: login
                    "accedi", // Italian: sign in
                    "entrar", // Portuguese: sign in (login is login;)
                    "inloggen", // Dutch: login
                    "aanmelden" // Dutch: sign in
                    );

    /* Less likely labels, but still worth trying */
    protected static List<String> LOGIN_LABELS_P2 =
            List.of("account", "signup", "sign up", "sign-up");

    private static final String HTTP_AUTH_EXCEPTION_TEXT = "This site is asking you to sign in.";

    protected static final int MIN_SESSION_COOKIE_LENGTH = 10;

    public static final int TIME_TO_SLEEP_IN_MSECS = 100;

    private static final int AUTH_PAGE_SLEEP_IN_MSECS = 2000;

    private static final Logger LOGGER = LogManager.getLogger(AuthUtils.class);

    private static final By ALL_SELECTOR = By.cssSelector("*");

    private static final String PASSWORD = "password";

    private static final String INPUT_TAG = "input";

    private static final HttpRequestConfig REDIRECT_NOTIFIER_CONFIG =
            HttpRequestConfig.builder()
                    .setRedirectionValidator(
                            new HttpRedirectionValidator() {

                                @Override
                                public boolean isValid(URI redirection) {
                                    return true;
                                }

                                @Override
                                public void notifyMessageReceived(HttpMessage message) {
                                    historyProvider.addAuthMessageToHistory(message);
                                }
                            })
                    .build();

    static final int MAX_UNAUTH_REDIRECTIONS = 50;

    private static AuthenticationBrowserHook browserHook;

    private static ExecutorService executorService;

    private static long timeToWaitMs = TimeUnit.SECONDS.toMillis(5);

    @Setter
    private static HistoryProvider historyProvider = ExtensionAuthhelper.getHistoryProvider();

    /**
     * These are session tokens that have been seen in responses but not yet seen in use. When they
     * are seen in use then they are removed.
     */
    private static Map<String, SessionToken> knownTokenMap =
            Collections.synchronizedMap(new HashMap<>());

    /**
     * Session tokens used in authentication requests. We keep track of them so that we can reuse
     * the last known good value, in the case where we don't see the token set in the authentication
     * response.
     */
    private static Map<Integer, Map<String, String>> requestTokenMap =
            Collections.synchronizedMap(new HashMap<>());

    /**
     * The best verification request we have found for a context. There will only be a verification
     * request recorded if the user has indicated that they want ZAP to auto-detect one by: setting
     * session management to auto-detect, setting the checking strategy to "poll" but not specified
     * a URL.
     */
    private static Map<Integer, VerificationRequestDetails> contextVerifMap =
            Collections.synchronizedMap(new HashMap<>());

    /**
     * The best session management request we have found for a context. There will only be a
     * verification request recorded if the user has indicated that they want ZAP to auto-detect one
     * by setting session management to auto-detect.
     */
    private static Map<Integer, SessionManagementRequestDetails> contextSessionMgmtMap =
            Collections.synchronizedMap(new HashMap<>());

    /**
     * The URLs (and methods) we've checked for finding good verification requests. These will only
     * be recorded if the user has set verification to auto-detect.
     */
    private static Map<Integer, Set<String>> contextVerificationCheckedMap =
            Collections.synchronizedMap(new HashMap<>());

    private static Map<Integer, Set<String>> contextVerificationAlwaysCheckMap =
            Collections.synchronizedMap(new HashMap<>());

    private static final List<Authenticator> AUTHENTICATORS;

    static {
        AUTHENTICATORS = List.of(new MsLoginAuthenticator(), new DefaultAuthenticator());
    }

    public static long getTimeToWaitMs() {
        return timeToWaitMs;
    }

    public static void setTimeToWaitMs(long timeToWaitMs) {
        AuthUtils.timeToWaitMs = timeToWaitMs;
    }

    public static long getWaitLoopCount() {
        return getTimeToWaitMs() / TIME_TO_SLEEP_IN_MSECS;
    }

    public static WebElement getUserField(
            WebDriver wd, List<WebElement> inputElements, WebElement passwordField) {
        return ignoreSeleniumExceptions(
                () -> getUserFieldInternal(wd, inputElements, passwordField));
    }

    private static WebElement getUserFieldInternal(
            WebDriver wd, List<WebElement> inputElements, WebElement passwordField) {
        List<WebElement> filteredList = displayed(inputElements).toList();
        if (filteredList.size() == 1) {
            WebElement element = filteredList.get(0);
            logFieldElement("Choosing only displayed", element);
            return element;
        }

        filteredList =
                filteredList.stream()
                        .filter(
                                elem -> {
                                    String type = getAttribute(elem, "type");
                                    return "text".equalsIgnoreCase(type)
                                            || "email".equalsIgnoreCase(type);
                                })
                        .toList();

        if (!filteredList.isEmpty()) {
            if (filteredList.size() > 1) {
                WebElement foundField = findFormUsernameField(wd, filteredList, passwordField);
                if (foundField != null) {
                    return foundField;
                }

                LOGGER.warn("Found more than one potential user field : {}", filteredList);
                // Try to identify the best one
                for (WebElement we : filteredList) {
                    if (isUsernameField(we)) {
                        logFieldElement("Choosing 'best' user", we);
                        return we;
                    }
                    logFieldElement("Not yet choosing user", we);
                }
            }

            WebElement element = filteredList.get(0);
            logFieldElement("Choosing first user", element);
            return element;
        }
        return null;
    }

    private static WebElement findFormUsernameField(
            WebDriver wd, List<WebElement> elements, WebElement field) {
        if (field == null) {
            return null;
        }

        WebElement form = getParentForm(wd, field);
        if (form == null) {
            return null;
        }

        List<WebElement> formFields =
                elements.stream().filter(e -> form.equals(getParentForm(wd, e))).toList();

        if (formFields.size() == 1) {
            WebElement element = formFields.get(0);
            logFieldElement("Choosing form user", element);
            return element;
        }

        for (WebElement we : formFields) {
            if (isUsernameField(we)) {
                logFieldElement("Choosing 'best' form user", we);
                return we;
            }
            logFieldElement("Not yet choosing form user", we);
        }

        WebElement element = formFields.get(0);
        logFieldElement("Choosing first form user", element);
        return element;
    }

    private static boolean isUsernameField(WebElement element) {
        return attributeContains(element, "id", USERNAME_FIELD_INDICATORS)
                || attributeContains(element, "name", USERNAME_FIELD_INDICATORS);
    }

    private static WebElement getParentForm(WebDriver wd, WebElement element) {
        if (wd instanceof JavascriptExecutor je) {
            return (WebElement) je.executeScript("return arguments[0].form", element);
        }
        return null;
    }

    private static void logFieldElement(String prefix, WebElement element) {
        LOGGER.debug(
                "{} field: name={} id={}",
                prefix,
                getAttribute(element, "name"),
                getAttribute(element, "id"));
    }

    private static String getAttribute(WebElement element, String name) {
        return element.getAttribute(name);
    }

    private static Stream<WebElement> displayed(List<WebElement> elements) {
        return elements.stream().filter(WebElement::isDisplayed);
    }

    static boolean attributeContains(WebElement we, String attribute, List<String> strings) {
        String att = getAttribute(we, attribute);
        if (att == null) {
            return false;
        }
        att = att.toLowerCase(Locale.ROOT);
        for (String str : strings) {
            if (att.contains(str)) {
                return true;
            }
        }
        return false;
    }

    public static WebElement getPasswordField(List<WebElement> inputElements) {
        return ignoreSeleniumExceptions(
                () ->
                        displayed(inputElements)
                                .filter(
                                        element ->
                                                PASSWORD.equalsIgnoreCase(
                                                        getAttribute(element, "type")))
                                .findFirst()
                                .orElseGet(
                                        () ->
                                                displayed(inputElements)
                                                        .filter(AuthUtils::hasPasswordAttributes)
                                                        .findFirst()
                                                        .orElse(null)));
    }

    private static boolean hasPasswordAttributes(WebElement element) {
        return Strings.CI.contains(getAttribute(element, "id"), PASSWORD)
                || Strings.CI.contains(getAttribute(element, "name"), PASSWORD);
    }

    /**
     * Executes the given supplier and ignores specific exceptions.
     *
     * @param supplier The function to execute.
     * @param exceptions The exceptions to ignore.
     * @return The result of the function or null if an exception is ignored.
     */
    public static <T> T ignoreSeleniumExceptions(Supplier<T> supplier) {
        try {
            return supplier.get();
        } catch (WebDriverException e) {
            // Ignore all selenium exceptions, especially StaleElementReferenceException
            LOGGER.debug(e.getMessage(), e);
        } catch (Exception e) {
            // These might be more relevant?
            LOGGER.warn(e.getMessage(), e);
        }
        return null;
    }

    public static boolean isAuthProvider(HttpMessage msg) {
        for (Authenticator authenticator : AUTHENTICATORS) {
            if (authenticator.isOwnSite(msg)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Authenticate as the given user, by filling in and submitting the login form
     *
     * @param diagnostics {@code true} if diagnostics should be recorded, {@code false} otherwise.
     * @param wd the WebDriver controlling the browser
     * @param user the user which is being used for authentication
     * @param loginPageUrl the URL of the login page
     * @return true if the login form was successfully submitted.
     */
    public static boolean authenticateAsUser(
            boolean diagnostics,
            WebDriver wd,
            User user,
            String loginPageUrl,
            int loginWaitInSecs,
            int stepDelayInSecs,
            List<AuthenticationStep> steps) {

        try (AuthenticationDiagnostics diags =
                new AuthenticationDiagnostics(
                        diagnostics,
                        new BrowserBasedAuthenticationMethodType().getName(),
                        user.getContext().getName(),
                        user.getName())) {
            return authenticateAsUserWithErrorStep(
                    diags, wd, user, loginPageUrl, loginWaitInSecs, stepDelayInSecs, steps);
        }
    }

    static boolean authenticateAsUserWithErrorStep(
            AuthenticationDiagnostics diags,
            WebDriver wd,
            User user,
            String loginPageUrl,
            int loginWaitInSecs,
            int stepDelayInSecs,
            List<AuthenticationStep> steps) {
        try {
            return authenticateAsUserImpl(
                    diags, wd, user, loginPageUrl, loginWaitInSecs, stepDelayInSecs, steps);
        } catch (Exception e) {
            diags.recordErrorStep(wd);
            throw e;
        }
    }

    private static boolean authenticateAsUserImpl(
            AuthenticationDiagnostics diags,
            WebDriver wd,
            User user,
            String loginPageUrl,
            int loginWaitInSecs,
            int stepDelayInSecs,
            List<AuthenticationStep> steps) {

        UsernamePasswordAuthenticationCredentials credentials = getCredentials(user);

        Context context = user.getContext();

        // Try with the given URL
        wd.get(loginPageUrl);
        boolean auth = false;
        try {
            auth =
                    internalAuthenticateAsUser(
                            diags,
                            wd,
                            context,
                            loginPageUrl,
                            credentials,
                            loginWaitInSecs,
                            stepDelayInSecs,
                            steps);
        } catch (Exception e) {
            if (e.getMessage() != null && e.getMessage().contains(HTTP_AUTH_EXCEPTION_TEXT)) {
                return handleHttpAuth(wd, context, credentials, loginPageUrl);
            }
            throw e;
        }

        if (auth) {
            return true;
        }

        // Try to find a login link - loop through the sets in priority order
        for (List<String> labelList : List.of(LOGIN_LABELS_P1, LOGIN_LABELS_P2)) {
            wd.get(loginPageUrl);
            sleep(AUTH_PAGE_SLEEP_IN_MSECS);
            List<WebElement> links = LoginLinkDetector.getLoginLinks(wd, labelList);
            if (!links.isEmpty()) {
                // Only try the first as we're only likely to get 1, and once we follow that then
                // subsequent links will be invalid. This may change based on real world feedback of
                // course.
                WebElement element = links.get(0);
                diags.recordStep(
                        wd,
                        Constant.messages.getString("authhelper.auth.method.diags.steps.loginlink"),
                        element);
                element.click();
                sleep(AUTH_PAGE_SLEEP_IN_MSECS);
                auth =
                        internalAuthenticateAsUser(
                                diags,
                                wd,
                                context,
                                loginPageUrl,
                                credentials,
                                loginWaitInSecs,
                                stepDelayInSecs,
                                steps);
                if (auth) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean handleHttpAuth(
            WebDriver wd,
            Context context,
            UsernamePasswordAuthenticationCredentials credentials,
            String loginPageUrl) {
        if (wd instanceof FirefoxDriver fxwd) {
            // Selenium currently only supports FX
            // Start by checking the creds with a direct request - its much easier to
            // detect auth failures this way
            // Will have already seen this URL before, but its probably a good verif one
            // now
            alwaysCheckContextVerificationMap(context, loginPageUrl);
            try {
                // Send an authenticated request so that we see what sort of HTTP auth is in use
                HttpSender unauthSender =
                        new HttpSender(HttpSender.AUTHENTICATION_HELPER_INITIATOR);
                unauthSender.setMaxRedirects(MAX_UNAUTH_REDIRECTIONS);

                URI uri = new URI(loginPageUrl, true);
                HttpMessage msg1 = new HttpMessage(uri);
                unauthSender.sendAndReceive(msg1, REDIRECT_NOTIFIER_CONFIG);

                String authHeader;
                if (NetworkUtils.isHttpBasicAuth(msg1)) {
                    authHeader = NetworkUtils.getHttpBasicAuthorization(credentials);
                    incStatsCounter(uri, AUTH_BROWSER_HTTP_AUTH_BASIC_STATS);
                } else if (NetworkUtils.isHttpDigestAuth(msg1)) {
                    // Do not currently support Digest auth, but lets record the stats
                    incStatsCounter(uri, AUTH_BROWSER_HTTP_AUTH_DIGEST_STATS);
                    return false;
                } else {
                    incStatsCounter(uri, AUTH_BROWSER_HTTP_AUTH_UNKNOWN_STATS);
                    return false;
                }

                // Now try to send an auth request - this will fail if the creds are wrong
                HttpMessage msg2 = new HttpMessage(uri);
                msg2.getRequestHeader().setHeader(HttpHeader.AUTHORIZATION, authHeader);
                unauthSender.sendAndReceive(msg2, REDIRECT_NOTIFIER_CONFIG);

                if (HttpStatusCode.isClientError(msg2.getResponseHeader().getStatusCode())) {
                    incStatsCounter(loginPageUrl, AUTH_BROWSER_HTTP_AUTH_FAILED_STATS);
                    return false;
                }

            } catch (Exception e1) {
                incStatsCounter(loginPageUrl, AUTH_BROWSER_HTTP_AUTH_FAILED_STATS);
                LOGGER.debug(e1.getMessage(), e1);
                return false;
            }
            try {
                // Attempt to get selenium to handle HTTP Auth
                fxwd.network()
                        .addAuthenticationHandler(
                                new UsernameAndPassword(
                                        credentials.getUsername(), credentials.getPassword()));

                // Need to wait for passive scanning of prev req to complete
                sleep(AUTH_PAGE_SLEEP_IN_MSECS);

                neverCheckContextVerificationMap(context, loginPageUrl);
                fxwd.get(loginPageUrl);

                incStatsCounter(loginPageUrl, AUTH_FOUND_FIELDS_STATS);
                incStatsCounter(loginPageUrl, AUTH_BROWSER_PASSED_STATS);
                incStatsCounter(loginPageUrl, AUTH_BROWSER_HTTP_AUTH_PASSED_STATS);
                return true;
            } catch (Exception e1) {
                incStatsCounter(loginPageUrl, AUTH_BROWSER_HTTP_AUTH_FAILED_STATS);
                LOGGER.debug(e1.getMessage(), e1);
            }
        } else {
            incStatsCounter(loginPageUrl, AUTH_BROWSER_HTTP_AUTH_NOT_SUPPORTED_STATS);
        }
        return false;
    }

    private static UsernamePasswordAuthenticationCredentials getCredentials(User user) {
        AuthenticationCredentials credentials = user.getAuthenticationCredentials();
        if (credentials instanceof UsernamePasswordAuthenticationCredentials creds) {
            return creds;
        }
        throw new UnsupportedAuthenticationCredentialsException(
                "Only username and password credential currently supported");
    }

    private static boolean internalAuthenticateAsUser(
            AuthenticationDiagnostics diags,
            WebDriver wd,
            Context context,
            String loginPageUrl,
            UsernamePasswordAuthenticationCredentials credentials,
            int waitInSecs,
            int stepDelayInSecs,
            List<AuthenticationStep> steps) {

        sleep(50);
        diags.recordStep(
                wd, Constant.messages.getString("authhelper.auth.method.diags.steps.start"));
        sleep(TimeUnit.SECONDS.toMillis(stepDelayInSecs));

        Authenticator.Result result = null;
        for (Authenticator authenticator : AUTHENTICATORS) {
            result =
                    authenticator.authenticate(
                            diags,
                            wd,
                            context,
                            loginPageUrl,
                            credentials,
                            stepDelayInSecs,
                            waitInSecs,
                            steps);

            if (!result.isAttempted()) {
                continue;
            }

            if (!result.isSuccessful()) {
                break;
            }

            diags.recordStep(
                    wd, Constant.messages.getString("authhelper.auth.method.diags.steps.finish"));

            incStatsCounter(loginPageUrl, AUTH_FOUND_FIELDS_STATS);
            incStatsCounter(loginPageUrl, AUTH_BROWSER_PASSED_STATS);
            AuthUtils.sleep(TimeUnit.SECONDS.toMillis(waitInSecs));

            if (context != null && context.getAuthenticationMethod().getPollUrl() == null) {
                // We failed to identify a suitable URL for polling.
                // This can happen for more traditional apps - refresh the current one in case
                // its a good option.
                wd.get(wd.getCurrentUrl());
                sleepMax(TimeUnit.SECONDS.toMillis(stepDelayInSecs), TIME_TO_SLEEP_IN_MSECS);
                diags.recordStep(
                        wd,
                        Constant.messages.getString("authhelper.auth.method.diags.steps.refresh"));
            }
            return true;
        }
        if (result == null || !result.hasUserField()) {
            incStatsCounter(loginPageUrl, AUTH_NO_USER_FIELD_STATS);
        }
        if (result == null || !result.hasPwdField()) {
            incStatsCounter(loginPageUrl, AUTH_NO_PASSWORD_FIELD_STATS);
        }
        incStatsCounter(loginPageUrl, AUTH_BROWSER_FAILED_STATS);
        return false;
    }

    public static List<WebElement> getInputElements(WebDriver wd, boolean includeShadow) {
        List<WebElement> selectedElements = wd.findElements(By.cssSelector(INPUT_TAG));
        if (!includeShadow && !selectedElements.isEmpty()) {
            return selectedElements;
        }

        Set<WebElement> allSelectedElements = new LinkedHashSet<>(selectedElements);
        addAllInputElements(wd.findElements(ALL_SELECTOR), allSelectedElements);
        return new ArrayList<>(allSelectedElements);
    }

    private static void addAllInputElements(
            List<WebElement> sourceElements, Set<WebElement> elements) {
        for (WebElement element : sourceElements) {
            try {
                if (INPUT_TAG.equalsIgnoreCase(element.getTagName())) {
                    elements.add(element);
                }

                addAllInputElements(element.getShadowRoot().findElements(ALL_SELECTOR), elements);
            } catch (StaleElementReferenceException | NoSuchShadowRootException e) {
                // Nothing to do.
            }
        }
    }

    public static void fillField(WebElement field, String value) {
        if (StringUtils.isNotEmpty(getAttribute(field, "value"))) {
            // Clear, otherwise sendKeys will append to any existing value
            field.clear();
        }
        field.sendKeys(value);
    }

    public static void fillUserName(
            AuthenticationDiagnostics diags,
            WebDriver wd,
            String username,
            WebElement field,
            int stepDelayInSecs) {
        fillField(field, username);
        diags.recordStep(
                wd,
                Constant.messages.getString("authhelper.auth.method.diags.steps.username"),
                field);
        sleep(TimeUnit.SECONDS.toMillis(stepDelayInSecs));
    }

    public static void fillPassword(
            AuthenticationDiagnostics diags,
            WebDriver wd,
            String password,
            WebElement field,
            int stepDelayInSecs) {
        fillField(field, password);
        diags.recordStep(
                wd,
                Constant.messages.getString("authhelper.auth.method.diags.steps.password"),
                field);
        sleep(TimeUnit.SECONDS.toMillis(stepDelayInSecs));
    }

    private static void sendReturn(
            AuthenticationDiagnostics diags, WebDriver wd, WebElement field) {
        field.sendKeys(Keys.RETURN);
        diags.recordStep(
                wd, Constant.messages.getString("authhelper.auth.method.diags.steps.return"));
    }

    public static void sendReturnAndSleep(
            AuthenticationDiagnostics diags, WebDriver wd, WebElement field, int stepDelayInSecs) {
        sendReturn(diags, wd, field);
        sleep(TimeUnit.SECONDS.toMillis(stepDelayInSecs));
    }

    public static void submit(
            AuthenticationDiagnostics diags,
            WebDriver wd,
            WebElement field,
            int stepDelayInSecs,
            int pageLoadWait) {
        sendReturnAndSleep(diags, wd, field, stepDelayInSecs);

        try {
            boolean invisible =
                    new WebDriverWait(wd, Duration.ofSeconds(pageLoadWait))
                            .until(ExpectedConditions.invisibilityOf(field));
            if (invisible) {
                return;
            }
        } catch (TimeoutException ignore) {
            // Nothing to do.
        }

        WebElement button;
        List<WebElement> buttons =
                wd.findElements(By.tagName("button")).stream()
                        .filter(WebElement::isDisplayed)
                        .filter(WebElement::isEnabled)
                        .toList();
        if (buttons.size() == 1) {
            button = buttons.get(0);
        } else {
            button =
                    buttons.stream()
                            .filter(e -> elementContainsText(e, LOGIN_LABELS_P1))
                            .findFirst()
                            .orElse(null);
        }

        if (button != null) {
            diags.recordStep(
                    wd,
                    Constant.messages.getString("authhelper.auth.method.diags.steps.click"),
                    button);
            button.click();
        }
    }

    private static boolean elementContainsText(WebElement element, List<String> searchTexts) {
        String txt = element.getText().toLowerCase(Locale.ROOT);
        return searchTexts.stream().anyMatch(txt::contains);
    }

    public static void incStatsCounter(String url, String stat) {
        try {
            incStatsCounter(new URI(url, true), stat);
        } catch (URIException e) {
            // Ignore
        }
    }

    public static void incStatsCounter(URI uri, String stat) {
        try {
            Stats.incCounter(SessionStructure.getHostName(uri), stat);
        } catch (URIException e) {
            // Ignore
        }
    }

    public static void sleepMax(long msec1, long msec2) {
        sleep(Math.max(msec1, msec2));
    }

    public static void sleep(long millisecs) {
        if (millisecs <= 0) {
            return;
        }
        try {
            Thread.sleep(millisecs);
        } catch (InterruptedException e) {
            // Ignore
        }
    }

    /**
     * A temporary method to enable browser based authentication whenever a browser is launched via
     * selenium. The first context found configured with browser based authentication and a user
     * will be chosen.
     */
    public static void enableBrowserAuthentication() {
        if (browserHook != null) {
            throw new IllegalStateException("BrowserHook already enabled");
        }
        ExtensionUserManagement extUser = getExtension(ExtensionUserManagement.class);
        if (extUser == null) {
            throw new IllegalStateException("Failed to access ExtensionUserManagement");
        }

        for (Context context : Model.getSingleton().getSession().getContexts()) {
            AuthenticationMethod method = context.getAuthenticationMethod();
            if (method instanceof BrowserBasedAuthenticationMethod) {
                for (User user : extUser.getContextUserAuthManager(context.getId()).getUsers()) {
                    AuthenticationCredentials creds = user.getAuthenticationCredentials();
                    if (creds instanceof UsernamePasswordAuthenticationCredentials) {
                        browserHook = new AuthenticationBrowserHook(context, user);
                        break;
                    }
                }
            }
            if (browserHook != null) {
                break;
            }
        }
        if (browserHook != null) {
            getExtension(ExtensionSelenium.class).registerBrowserHook(browserHook);
        } else {
            throw new IllegalStateException("Failed to find suitable context and user");
        }
    }

    /**
     * A temporary method to enable browser based authentication whenever a browser is launched via
     * selenium.
     *
     * @param context the context, which must use browser based auth
     * @param userName the name of the user, which must be present in the context
     */
    public static void enableBrowserAuthentication(Context context, String userName) {
        if (browserHook != null) {
            throw new IllegalStateException("BrowserHook already enabled");
        }
        browserHook = new AuthenticationBrowserHook(context, userName);

        getExtension(ExtensionSelenium.class).registerBrowserHook(browserHook);
    }

    /** A temporary method for disabling browser based authentication. */
    public static void disableBrowserAuthentication() {
        if (browserHook != null) {
            getExtension(ExtensionSelenium.class).deregisterBrowserHook(browserHook);
            browserHook = null;
        }
    }

    /**
     * Returns all of the identified session token labels in the given message
     *
     * @param msg the message to extract the tokens from
     * @return all of the identified session token labels in the given message
     */
    public static Map<String, SessionToken> getResponseSessionTokens(HttpMessage msg) {
        Map<String, SessionToken> map = new HashMap<>();

        Arrays.stream(HEADERS)
                .forEach(
                        h -> {
                            for (String v : msg.getResponseHeader().getHeaderValues(h)) {
                                addToMap(map, new SessionToken(SessionToken.HEADER_SOURCE, h, v));
                            }
                        });

        List<HttpCookie> cookies = msg.getResponseHeader().getHttpCookies(null);
        for (HttpCookie cookie : cookies) {
            if (cookie.getValue().length() >= MIN_SESSION_COOKIE_LENGTH) {
                addToMap(
                        map,
                        new SessionToken(
                                SessionToken.COOKIE_SOURCE, cookie.getName(), cookie.getValue()));
            }
        }

        String responseData = msg.getResponseBody().toString();
        if (msg.getResponseHeader().isJson()
                && StringUtils.isNotBlank(responseData)
                && !extractJsonString(map, responseData)) {
            Map<String, SessionToken> tokens = new HashMap<>();
            try {
                try {
                    AuthUtils.extractJsonTokens(JSONObject.fromObject(responseData), "", tokens);
                } catch (JSONException e) {
                    AuthUtils.extractJsonTokens(JSONArray.fromObject(responseData), "", tokens);
                }
                for (SessionToken token : tokens.values()) {
                    String tokenLc = token.getKey().toLowerCase(Locale.ROOT);
                    for (String id : JSON_IDS) {
                        if (tokenLc.equals(id) || tokenLc.endsWith("." + id)) {
                            addToMap(map, token);
                            break;
                        }
                    }
                }
            } catch (JSONException | ClassCastException e) {
                LOGGER.debug(
                        "Unable to parse authentication response body from {} as JSON: {} ",
                        msg.getRequestHeader().getURI(),
                        responseData,
                        e);
            }
        }
        if (!map.isEmpty()) {
            LOGGER.debug("Found session tokens in {} : {}", msg.getRequestHeader().getURI(), map);
            map.forEach(
                    (k, v) ->
                            AuthUtils.incStatsCounter(
                                    msg.getRequestHeader().getURI(),
                                    AUTH_SESSION_TOKEN_STATS_PREFIX + v.getKey()));
        }

        return map;
    }

    private static boolean extractJsonString(Map<String, SessionToken> map, String response) {
        if (response.startsWith("\"") && JSONUtils.isString(response)) {
            String value = JSONUtils.stripQuotes(response);
            if (value.isBlank()) {
                return true;
            }

            addToMap(map, new SessionToken(SessionToken.JSON_SOURCE, "", value));
            return true;
        }
        return false;
    }

    public static List<Pair<String, String>> getHeaderTokens(
            HttpMessage msg, List<SessionToken> tokens, boolean incCookies) {
        List<Pair<String, String>> list = new ArrayList<>();
        for (SessionToken token : new TreeSet<>(tokens)) {
            for (HttpHeaderField header : msg.getRequestHeader().getHeaders()) {
                if (HttpHeader.COOKIE.equalsIgnoreCase(header.getName())) {
                    // Handle cookies below so we can separate them out
                    continue;
                }
                if (header.getValue().contains(token.getValue())) {
                    String hv =
                            header.getValue()
                                    .replace(token.getValue(), "{%" + token.getToken() + "%}");
                    list.add(new Pair<>(header.getName(), hv));
                }
            }
            if (incCookies) {
                for (HttpCookie cookie : msg.getRequestHeader().getHttpCookies()) {
                    if (!(SessionToken.COOKIE_SOURCE.equals(token.getSource())
                                    && cookie.getName().equals(token.getKey()))
                            && cookie.getValue().contains(token.getValue())) {
                        String hv =
                                cookie.getValue()
                                        .replace(token.getValue(), "{%" + token.getToken() + "%}");
                        list.add(new Pair<>(HttpHeader.COOKIE, cookie.getName() + "=" + hv));
                    }
                }
            }
        }
        return list;
    }

    public static void logUserMessage(Level level, String str) {
        LOGGER.log(level, str);
        if (View.isInitialised()) {
            View.getSingleton().getOutputPanel().append(str + "\n");
        }
    }

    protected static void addToMap(Map<String, SessionToken> map, SessionToken token) {
        map.put(token.getToken(), token);
    }

    public static Map<String, SessionToken> getAllTokens(HttpMessage msg, boolean incReqCookies) {
        Map<String, SessionToken> tokens = new HashMap<>();
        String responseData = msg.getResponseBody().toString();
        if (msg.getResponseHeader().isJson()
                && StringUtils.isNotBlank(responseData)
                && !extractJsonString(tokens, responseData)) {
            // Extract json response data
            try {
                try {
                    AuthUtils.extractJsonTokens(JSONObject.fromObject(responseData), "", tokens);
                } catch (JSONException e) {
                    AuthUtils.extractJsonTokens(JSONArray.fromObject(responseData), "", tokens);
                }
            } catch (JSONException e) {
                LOGGER.debug(
                        "Unable to parse authentication response body from {} as JSON: {}",
                        msg.getRequestHeader().getURI(),
                        responseData);
            }
        }
        // Add response headers
        msg.getResponseHeader()
                .getHeaders()
                .forEach(
                        h ->
                                addToMap(
                                        tokens,
                                        new SessionToken(
                                                SessionToken.HEADER_SOURCE,
                                                h.getName(),
                                                h.getValue())));

        // Add URL params
        msg.getUrlParams()
                .forEach(
                        p ->
                                addToMap(
                                        tokens,
                                        new SessionToken(
                                                SessionToken.URL_SOURCE,
                                                p.getName(),
                                                p.getValue())));
        // Add Cookies
        if (incReqCookies) {
            msg.getRequestHeader()
                    .getCookieParams()
                    .forEach(
                            c ->
                                    addToMap(
                                            tokens,
                                            new SessionToken(
                                                    SessionToken.COOKIE_SOURCE,
                                                    c.getName(),
                                                    c.getValue())));
        }
        msg.getResponseHeader()
                .getHttpCookies(null)
                .forEach(
                        c ->
                                addToMap(
                                        tokens,
                                        new SessionToken(
                                                SessionToken.COOKIE_SOURCE,
                                                c.getName(),
                                                c.getValue())));

        return tokens;
    }

    /**
     * Returns all of the identified session tokens in a request. This method looks for any headers
     * with "auth" in their names and cookies with a value over a minimum length.
     *
     * @param msg the message containing the request to check
     * @return all of the identified session tokens in the request.
     */
    public static Set<SessionToken> getRequestSessionTokens(HttpMessage msg) {
        return getRequestSessionTokens(msg, List.of());
    }

    private static boolean isAuthHeader(String name) {
        return name.toLowerCase(Locale.ROOT).contains("auth");
    }

    public static Set<SessionToken> getRequestSessionTokens(
            HttpMessage msg, List<Pair<String, String>> headerConfigs) {
        Set<SessionToken> map = new HashSet<>();
        msg.getRequestHeader().getHeaders().stream()
                .filter(h -> isAuthHeader(h.getName()))
                .forEach(
                        h ->
                                map.add(
                                        new SessionToken(
                                                SessionToken.HEADER_SOURCE,
                                                h.getName(),
                                                h.getValue())));

        if (headerConfigs != null) {
            for (Pair<String, String> entry : headerConfigs) {
                String name = entry.first;
                if (isAuthHeader(name) || HttpHeader.COOKIE.equalsIgnoreCase(name)) {
                    continue;
                }

                for (String value : msg.getRequestHeader().getHeaderValues(name)) {
                    map.add(new SessionToken(SessionToken.HEADER_SOURCE, name, value));
                }
            }
        }
        List<HttpCookie> cookies = msg.getRequestHeader().getHttpCookies();
        for (HttpCookie cookie : cookies) {
            if (cookie.getValue().length() >= MIN_SESSION_COOKIE_LENGTH) {
                map.add(
                        new SessionToken(
                                SessionToken.COOKIE_SOURCE, cookie.getName(), cookie.getValue()));
            }
        }

        return map;
    }

    static SessionManagementRequestDetails findSessionTokenSource(String token) {
        return findSessionTokenSource(token, -1);
    }

    public static SessionManagementRequestDetails findSessionTokenSource(
            String token, int firstId) {
        return historyProvider.findSessionTokenSource(token, firstId);
    }

    public static void extractJsonTokens(
            JSONObject jsonObject, String parent, Map<String, SessionToken> tokens) {
        for (Object key : jsonObject.keySet()) {
            Object obj = jsonObject.get(key);
            extractJsonTokens(obj, normalisedKey(parent, (String) key), tokens);
        }
    }

    private static void extractJsonTokens(
            Object obj, String parent, Map<String, SessionToken> tokens) {
        if (obj instanceof JSONObject jObj) {
            extractJsonTokens(jObj, parent, tokens);
        } else if (obj instanceof JSONArray jArr) {
            Object[] oa = jArr.toArray();
            for (int i = 0; i < oa.length; i++) {
                extractJsonTokens(oa[i], parent + "[" + i + "]", tokens);
            }
        } else if (obj instanceof String str) {
            addToMap(tokens, new SessionToken(SessionToken.JSON_SOURCE, parent, str));
        }
    }

    private static String normalisedKey(String parent, String key) {
        return parent.isEmpty() ? key : parent + "." + key;
    }

    public static <T extends Extension> T getExtension(Class<T> clazz) {
        return Control.getSingleton().getExtensionLoader().getExtension(clazz);
    }

    public static void recordSessionToken(SessionToken token) {
        knownTokenMap.put(token.getValue(), token);
        Stats.setHighwaterMark(AUTH_SESSION_TOKENS_MAX, knownTokenMap.size());
    }

    public static SessionToken getSessionToken(String value) {
        return knownTokenMap.get(value);
    }

    public static SessionToken containsSessionToken(String value) {
        Optional<Entry<String, SessionToken>> entry;
        synchronized (knownTokenMap) {
            entry =
                    knownTokenMap.entrySet().stream()
                            .filter(m -> value.contains(m.getKey()))
                            .findFirst();
        }
        if (entry.isPresent()) {
            return entry.get().getValue();
        }
        return null;
    }

    static void removeSessionToken(SessionToken token) {
        knownTokenMap.remove(token.getValue());
    }

    public static void clean() {
        knownTokenMap.clear();
        contextVerifMap.clear();
        contextSessionMgmtMap.clear();
        contextVerificationCheckedMap.clear();
        contextVerificationAlwaysCheckMap.clear();
        requestTokenMap.clear();
        if (executorService != null) {
            executorService.shutdown();
            executorService = null;
        }
    }

    public static List<Context> getRelatedContexts(HttpMessage msg) {
        List<Context> contextList =
                Model.getSingleton()
                        .getSession()
                        .getContextsForUrl(msg.getRequestHeader().getURI().toString());
        String referer = msg.getRequestHeader().getHeader(HttpHeader.REFERER);
        if (StringUtils.isNotBlank(referer)) {
            contextList.addAll(Model.getSingleton().getSession().getContextsForUrl(referer));
        }

        return contextList;
    }

    static User getUser(Context context, String userName) {
        ExtensionUserManagement extUser = getExtension(ExtensionUserManagement.class);
        if (extUser == null) {
            throw new IllegalStateException("Failed to access ExtensionUserManagement");
        }
        Optional<User> oUser =
                extUser.getContextUserAuthManager(context.getId()).getUsers().stream()
                        .filter(u -> u.getName().equals(userName))
                        .findAny();
        if (oUser.isEmpty()) {
            throw new IllegalStateException("Failed to find user " + userName);
        }
        return oUser.get();
    }

    public static VerificationRequestDetails getVerificationDetailsForContext(int contextId) {
        return contextVerifMap.get(contextId);
    }

    public static void setVerificationDetailsForContext(
            int contextId, VerificationRequestDetails details) {
        contextVerifMap.put(contextId, details);
    }

    public static SessionManagementRequestDetails getSessionManagementDetailsForContext(
            int contextId) {
        return contextSessionMgmtMap.get(contextId);
    }

    public static void setSessionManagementDetailsForContext(
            int contextId, SessionManagementRequestDetails details) {
        contextSessionMgmtMap.put(contextId, details);
    }

    private static synchronized ExecutorService getExecutorService() {
        if (executorService == null) {
            executorService =
                    Executors.newSingleThreadExecutor(
                            new AuthThreadFactory("ZAP-Auth-Verif-Server"));
        }
        return executorService;
    }

    private static void alwaysCheckContextVerificationMap(Context context, String url) {
        contextVerificationAlwaysCheckMap
                .computeIfAbsent(context.getId(), c -> Collections.synchronizedSet(new HashSet<>()))
                .add("GET " + url);
    }

    private static void neverCheckContextVerificationMap(Context context, String url) {
        contextVerificationAlwaysCheckMap
                .computeIfAbsent(context.getId(), c -> Collections.synchronizedSet(new HashSet<>()))
                .remove("GET " + url);
    }

    public static void processVerificationDetails(
            Context context,
            VerificationRequestDetails details,
            VerificationDetectionScanRule rule) {

        String methodUrl =
                details.getMsg().getRequestHeader().getMethod()
                        + " "
                        + details.getMsg().getRequestHeader().getURI().toString();

        if (contextVerificationAlwaysCheckMap
                        .computeIfAbsent(
                                context.getId(), c -> Collections.synchronizedSet(new HashSet<>()))
                        .contains(methodUrl)
                || contextVerificationCheckedMap
                        .computeIfAbsent(
                                context.getId(), c -> Collections.synchronizedSet(new HashSet<>()))
                        .add(methodUrl)) {
            // Have not already checked this method + url
            getExecutorService().submit(new VerificationDetectionProcessor(context, details, rule));
        }
    }

    public static void recordRequestSessionToken(Context context, String key, String value) {
        recordRequestSessionToken(context.getId(), key, value);
    }

    private static Map<String, String> computeIfAbsent(
            Map<Integer, Map<String, String>> inputMap, int contextId) {
        return inputMap.computeIfAbsent(
                contextId, c -> Collections.synchronizedMap(new HashMap<>()));
    }

    public static void recordRequestSessionToken(int contextId, String key, String value) {
        computeIfAbsent(requestTokenMap, contextId).put(key.toLowerCase(Locale.ROOT), value);
    }

    public static String getRequestSessionToken(Context context, String key) {
        return getRequestSessionToken(context.getId(), key);
    }

    public static String getRequestSessionToken(int contextId, String key) {
        return computeIfAbsent(requestTokenMap, contextId).get(key.toLowerCase(Locale.ROOT));
    }

    static class AuthenticationBrowserHook implements BrowserHook {

        private BrowserBasedAuthenticationMethod bbaMethod;
        private User user;

        AuthenticationBrowserHook(Context context, String userName) {
            this(context, getUser(context, userName));
        }

        AuthenticationBrowserHook(Context context, User user) {
            this.user = user;
            AuthenticationMethod method = context.getAuthenticationMethod();
            if (!(method instanceof BrowserBasedAuthenticationMethod)) {
                throw new IllegalStateException("Unsupported method " + method.getType().getName());
            }
            bbaMethod = (BrowserBasedAuthenticationMethod) method;
        }

        @Override
        public void browserLaunched(SeleniumScriptUtils ssutils) {
            LOGGER.debug("AuthenticationBrowserHook - authenticating as {}", user.getName());
            bbaMethod.authenticate(ssutils.getWebDriver(), user);
        }
    }

    protected static class AuthThreadFactory implements ThreadFactory {

        private final AtomicInteger threadNumber;
        private final String namePrefix;
        private final ThreadGroup group;

        public AuthThreadFactory(String namePrefix) {
            threadNumber = new AtomicInteger(1);
            this.namePrefix = namePrefix;
            group = Thread.currentThread().getThreadGroup();
        }

        @Override
        public Thread newThread(Runnable r) {
            Thread t = new Thread(group, r, namePrefix + threadNumber.getAndIncrement(), 0);
            if (t.isDaemon()) {
                t.setDaemon(false);
            }
            if (t.getPriority() != Thread.NORM_PRIORITY) {
                t.setPriority(Thread.NORM_PRIORITY);
            }
            return t;
        }
    }

    public static boolean isRelevantToAuth(HttpMessage msg) {
        return !(ResourceIdentificationUtils.isImage(msg)
                || ResourceIdentificationUtils.isFont(msg)
                || ResourceIdentificationUtils.isCss(msg)
                || ResourceIdentificationUtils.isJavaScript(msg));
    }

    /**
     * If the auth checking strategy is set to auto-detect then this method will try to find a
     * suitable verification URL. This works best with more traditional web apps where a login link
     * is returned in HTML. The method first tries the URL without a path before falling back to the
     * given URL.
     */
    public static void checkLoginLinkVerification(
            HttpSender authSender, User user, String loginUrl) {
        AuthCheckingStrategy verif =
                user.getContext().getAuthenticationMethod().getAuthCheckingStrategy();
        if (!AuthCheckingStrategy.AUTO_DETECT.equals(verif)) {
            return;
        }
        try {
            URI testUri = new URI(loginUrl, true);
            if (!StringUtils.isEmpty(testUri.getPath())) {
                // Try to top level link first, if the page has the login form then its less likely
                // to have a link to one
                testUri.setPath("");
                if (checkLoginLinkVerification(authSender, user, testUri)) {
                    // The top level URL worked :)
                    return;
                }
                testUri = new URI(loginUrl, true);
            }
            checkLoginLinkVerification(authSender, user, testUri);

        } catch (Exception e) {
            LOGGER.warn(
                    "Failed accessing potential login link verification URL {}, {}",
                    loginUrl,
                    e.getMessage(),
                    e);
        }
    }

    private static boolean checkLoginLinkVerification(
            HttpSender authSender, User user, URI testUri) {
        try {
            // Send an unauthenticated req to the test site, manually following redirects as needed
            HttpMessage msg = new HttpMessage(testUri);
            HttpSender unauthSender = new HttpSender(HttpSender.AUTHENTICATION_HELPER_INITIATOR);
            unauthSender.setMaxRedirects(MAX_UNAUTH_REDIRECTIONS);
            unauthSender.sendAndReceive(msg, REDIRECT_NOTIFIER_CONFIG);

            if (!msg.getResponseHeader().isHtml()) {
                LOGGER.debug(
                        "Response to {} is no good as a login link verification req, it is not HTML {}",
                        testUri,
                        msg.getResponseHeader().getNormalisedContentTypeValue());
                return false;
            }
            String unauthBody = msg.getResponseBody().toString();
            Source src = new Source(unauthBody);
            List<Element> elements = LoginLinkDetector.getLoginLinks(src, LOGIN_LABELS_P1);
            if (elements.isEmpty()) {
                elements = LoginLinkDetector.getLoginLinks(src, LOGIN_LABELS_P2);
            }
            if (elements.isEmpty()) {
                return false;
            }
            String link = elements.get(0).toString();
            if (!unauthBody.contains(link)) {
                LOGGER.debug(
                        "Response to {} is no good as a login link verification req, no login link found",
                        testUri);
                return false;
            }
            // We've found a login link, now try an authenticated request
            HttpMessage authMsg = new HttpMessage(testUri);
            authSender.sendAndReceive(authMsg, true);
            historyProvider.addAuthMessageToHistory(authMsg);

            String authBody = authMsg.getResponseBody().toString();
            if (authBody.contains(link)) {
                LOGGER.debug(
                        "Response to {} is no good as a login link verification req, an authenticated request also includes the link {}",
                        testUri,
                        link);
                return false;
            }
            LOGGER.debug(
                    "Found good login link verification req {}, contains login link {}",
                    testUri,
                    link);

            AuthenticationMethod authMethod = user.getContext().getAuthenticationMethod();
            authMethod.setAuthCheckingStrategy(AuthCheckingStrategy.POLL_URL);
            authMethod.setPollUrl(testUri.toString());
            authMethod.setLoggedOutIndicatorPattern(Pattern.quote(link));
            return true;

        } catch (Exception e) {
            LOGGER.warn(
                    "Failed accessing potential login link verification URL {}, {}",
                    testUri,
                    e.getMessage(),
                    e);
            return false;
        }
    }

    public static boolean isRelevantToAuthDiags(HttpMessage msg) {
        if (!isRelevantToAuth(msg)) {
            return false;
        }

        String host =
                new String(msg.getRequestHeader().getURI().getRawHost()).toLowerCase(Locale.ROOT);
        // Strip out a few requests that can be expected to be unrelated
        return !(host.contains("clients2.google")
                || host.contains("detectportal.firefox")
                || host.contains("google-analytics")
                || host.contains("mozilla")
                || host.contains("safebrowsing-cache"));
    }

    public static void setMinWaitFor(ZestScript script, int minWaitForMsec) {
        for (int i = 0; i < script.getStatements().size(); i++) {
            setMinWaitFor(script.getStatements().get(i), minWaitForMsec);
        }
    }

    private static void setMinWaitFor(ZestStatement stmt, int minWaitForMsec) {
        if (stmt instanceof ZestClientElement cElmt) {
            if (cElmt.getWaitForMsec() < minWaitForMsec) {
                cElmt.setWaitForMsec(minWaitForMsec);
            }
        }
    }
}
