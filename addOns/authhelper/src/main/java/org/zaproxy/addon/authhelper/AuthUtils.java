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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Optional;
import java.util.Set;
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
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openqa.selenium.By;
import org.openqa.selenium.JavascriptExecutor;
import org.openqa.selenium.Keys;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebDriverException;
import org.openqa.selenium.WebElement;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpHeaderField;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.parosproxy.paros.network.HttpSender;
import org.parosproxy.paros.network.HttpStatusCode;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.authhelper.BrowserBasedAuthenticationMethodType.BrowserBasedAuthenticationMethod;
import org.zaproxy.addon.authhelper.internal.AuthenticationStep;
import org.zaproxy.addon.commonlib.ResourceIdentificationUtils;
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
import org.zaproxy.zap.session.WebSession;
import org.zaproxy.zap.users.User;
import org.zaproxy.zap.utils.Pair;
import org.zaproxy.zap.utils.Stats;

public class AuthUtils {

    public static final String AUTH_NO_USER_FIELD_STATS = "stats.auth.browser.nouserfield";
    public static final String AUTH_NO_PASSWORD_FIELD_STATS = "stats.auth.browser.nopasswordfield";
    public static final String AUTH_FOUND_FIELDS_STATS = "stats.auth.browser.foundfields";
    public static final String AUTH_SESSION_TOKEN_STATS_PREFIX = "stats.auth.sessiontoken.";
    public static final String AUTH_SESSION_TOKENS_MAX = "stats.auth.sessiontokens.max";
    public static final String AUTH_BROWSER_PASSED_STATS = "stats.auth.browser.passed";
    public static final String AUTH_BROWSER_FAILED_STATS = "stats.auth.browser.failed";

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

    protected static final int MIN_SESSION_COOKIE_LENGTH = 10;

    public static final int TIME_TO_SLEEP_IN_MSECS = 100;

    private static final int DEMO_SLEEP_IN_MSECS = 2000;

    private static final int AUTH_PAGE_SLEEP_IN_MSECS = 2000;

    private static final Logger LOGGER = LogManager.getLogger(AuthUtils.class);

    private static AuthenticationBrowserHook browserHook;

    private static ExecutorService executorService;

    private static long timeToWaitMs = TimeUnit.SECONDS.toMillis(5);

    private static boolean demoMode;

    @Setter private static HistoryProvider historyProvider = new HistoryProvider();

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
    private static Map<Integer, Set<String>> contextVerificationMap =
            Collections.synchronizedMap(new HashMap<>());

    public static long getTimeToWaitMs() {
        return timeToWaitMs;
    }

    public static void setTimeToWaitMs(long timeToWaitMs) {
        AuthUtils.timeToWaitMs = timeToWaitMs;
    }

    public static long getWaitLoopCount() {
        return getTimeToWaitMs() / TIME_TO_SLEEP_IN_MSECS;
    }

    static WebElement getUserField(
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
        String value = element.getDomAttribute(name);
        if (value != null) {
            return value;
        }
        return element.getDomProperty(name);
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

    static WebElement getPasswordField(List<WebElement> inputElements) {
        return ignoreSeleniumExceptions(
                () ->
                        displayed(inputElements)
                                .filter(
                                        element ->
                                                "password"
                                                        .equalsIgnoreCase(
                                                                getAttribute(element, "type")))
                                .findFirst()
                                .orElse(null));
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
            int waitInSecs,
            List<AuthenticationStep> steps) {

        try (AuthenticationDiagnostics diags =
                new AuthenticationDiagnostics(
                        diagnostics,
                        new BrowserBasedAuthenticationMethodType().getName(),
                        user.getContext().getName(),
                        user.getName())) {
            return authenticateAsUserImpl(diags, wd, user, loginPageUrl, waitInSecs, steps);
        }
    }

    static boolean authenticateAsUserImpl(
            AuthenticationDiagnostics diags,
            WebDriver wd,
            User user,
            String loginPageUrl,
            int waitInSecs,
            List<AuthenticationStep> steps) {

        UsernamePasswordAuthenticationCredentials credentials = getCredentials(user);

        Context context = user.getContext();

        // Try with the given URL
        wd.get(loginPageUrl);
        boolean auth =
                internalAuthenticateAsUser(
                        diags, wd, context, loginPageUrl, credentials, waitInSecs, steps);

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
                                diags, wd, context, loginPageUrl, credentials, waitInSecs, steps);
                if (auth) {
                    return true;
                }
            }
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
            List<AuthenticationStep> steps) {

        sleep(50);
        diags.recordStep(
                wd, Constant.messages.getString("authhelper.auth.method.diags.steps.start"));
        if (demoMode) {
            sleep(DEMO_SLEEP_IN_MSECS);
        }

        String username = credentials.getUsername();
        String password = credentials.getPassword();

        WebElement userField = null;
        WebElement pwdField = null;
        boolean userAdded = false;
        boolean pwdAdded = false;

        Iterator<AuthenticationStep> it = steps.stream().sorted().iterator();
        for (; it.hasNext(); ) {
            AuthenticationStep step = it.next();
            if (!step.isEnabled()) {
                continue;
            }

            if (step.getType() == AuthenticationStep.Type.AUTO_STEPS) {
                break;
            }

            WebElement element = step.execute(wd, credentials);
            diags.recordStep(wd, step.getDescription(), element);

            switch (step.getType()) {
                case USERNAME:
                    userField = element;
                    userAdded = true;
                    break;

                case PASSWORD:
                    pwdField = element;
                    pwdAdded = true;
                    break;

                default:
            }

            sleep(demoMode ? DEMO_SLEEP_IN_MSECS : TIME_TO_SLEEP_IN_MSECS);
        }

        for (int i = 0; i < getWaitLoopCount(); i++) {
            if ((userField != null || userAdded) && pwdField != null) {
                break;
            }

            List<WebElement> inputElements = wd.findElements(By.xpath("//input"));
            pwdField = getPasswordField(inputElements);
            userField = getUserField(wd, inputElements, pwdField);

            if (i > 1 && userField != null && pwdField == null && !userAdded) {
                // Handle pages which require you to submit the username first
                LOGGER.debug("Submitting just user field on {}", loginPageUrl);
                fillUserName(diags, wd, username, userField);
                sendReturnAndSleep(diags, wd, userField);
                userAdded = true;
            }
            sleep(TIME_TO_SLEEP_IN_MSECS);
        }
        if (userField != null && pwdField != null) {
            if (!userAdded) {
                LOGGER.debug("Entering user field on {}", wd.getCurrentUrl());
                fillUserName(diags, wd, username, userField);
            }
            try {
                if (!pwdAdded) {
                    LOGGER.debug("Submitting password field on {}", wd.getCurrentUrl());
                    fillPassword(diags, wd, password, pwdField);
                }
                sendReturn(diags, wd, pwdField);
            } catch (Exception e) {
                // Handle the case where the password field was present but hidden / disabled
                LOGGER.debug("Handling hidden password field on {}", wd.getCurrentUrl());
                sendReturnAndSleep(diags, wd, userField);
                sleep(TIME_TO_SLEEP_IN_MSECS);
                fillPassword(diags, wd, password, pwdField);
                sendReturn(diags, wd, pwdField);
            }

            for (; it.hasNext(); ) {
                AuthenticationStep step = it.next();
                if (!step.isEnabled()) {
                    continue;
                }

                step.execute(wd, credentials);
                diags.recordStep(wd, step.getDescription());

                sleep(demoMode ? DEMO_SLEEP_IN_MSECS : TIME_TO_SLEEP_IN_MSECS);
            }
            diags.recordStep(
                    wd, Constant.messages.getString("authhelper.auth.method.diags.steps.finish"));

            incStatsCounter(loginPageUrl, AUTH_FOUND_FIELDS_STATS);
            incStatsCounter(loginPageUrl, AUTH_BROWSER_PASSED_STATS);
            AuthUtils.sleep(TimeUnit.SECONDS.toMillis(waitInSecs));

            if (context != null) {
                if (context.getAuthenticationMethod().getPollUrl() == null) {
                    // We failed to identify a suitable URL for polling.
                    // This can happen for more traditional apps - refresh the current one in case
                    // its a good option.
                    wd.get(wd.getCurrentUrl());
                    AuthUtils.sleep(TimeUnit.SECONDS.toMillis(1));
                    diags.recordStep(
                            wd,
                            Constant.messages.getString(
                                    "authhelper.auth.method.diags.steps.refresh"));
                }
            }
            return true;
        }
        if (userField == null) {
            incStatsCounter(loginPageUrl, AUTH_NO_USER_FIELD_STATS);
        }
        if (pwdField == null) {
            incStatsCounter(loginPageUrl, AUTH_NO_PASSWORD_FIELD_STATS);
        }
        incStatsCounter(loginPageUrl, AUTH_BROWSER_FAILED_STATS);
        return false;
    }

    private static void fillUserName(
            AuthenticationDiagnostics diags, WebDriver wd, String username, WebElement field) {
        field.sendKeys(username);
        diags.recordStep(
                wd,
                Constant.messages.getString("authhelper.auth.method.diags.steps.username"),
                field);
        if (demoMode) {
            sleep(DEMO_SLEEP_IN_MSECS);
        }
    }

    private static void fillPassword(
            AuthenticationDiagnostics diags, WebDriver wd, String password, WebElement field) {
        field.sendKeys(password);
        diags.recordStep(
                wd,
                Constant.messages.getString("authhelper.auth.method.diags.steps.password"),
                field);
        if (demoMode) {
            sleep(DEMO_SLEEP_IN_MSECS);
        }
    }

    private static void sendReturn(
            AuthenticationDiagnostics diags, WebDriver wd, WebElement field) {
        field.sendKeys(Keys.RETURN);
        diags.recordStep(
                wd, Constant.messages.getString("authhelper.auth.method.diags.steps.return"));
    }

    private static void sendReturnAndSleep(
            AuthenticationDiagnostics diags, WebDriver wd, WebElement field) {
        sendReturn(diags, wd, field);
        if (demoMode) {
            sleep(DEMO_SLEEP_IN_MSECS);
        }
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

    public static void sleep(long millisecs) {
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

    public static void setDemoMode(boolean demo) {
        demoMode = demo;
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
        if (msg.getResponseHeader().isJson() && StringUtils.isNotBlank(responseData)) {
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
            } catch (JSONException e) {
                LOGGER.debug(
                        "Unable to parse authentication response body from {} as JSON: {} ",
                        msg.getRequestHeader().getURI().toString(),
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

    public static List<Pair<String, String>> getHeaderTokens(
            HttpMessage msg, List<SessionToken> tokens, boolean incCookies) {
        List<Pair<String, String>> list = new ArrayList<>();
        for (SessionToken token : tokens) {
            for (HttpHeaderField header : msg.getRequestHeader().getHeaders()) {
                if (HttpHeader.COOKIE.equalsIgnoreCase(header.getName())) {
                    // Handle cookies below so we can separate them out
                    continue;
                }
                if (header.getValue().contains(token.getValue())) {
                    String hv =
                            header.getValue()
                                    .replace(token.getValue(), "{%" + token.getToken() + "%}");
                    list.add(new Pair<String, String>(header.getName(), hv));
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
        if (msg.getResponseHeader().isJson() && StringUtils.isNotBlank(responseData)) {
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
                        msg.getRequestHeader().getURI().toString(),
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
     * Returns all of the identified session tokens in a request. This method looks for
     * Authorization headers and cookies with a value over a minimum length.
     *
     * @param msg the message containing the request to check
     * @return all of the identified session tokens in the request.
     */
    public static Set<SessionToken> getRequestSessionTokens(HttpMessage msg) {
        Set<SessionToken> map = new HashSet<>();
        List<String> authHeaders = msg.getRequestHeader().getHeaderValues(HttpHeader.AUTHORIZATION);
        for (String header : authHeaders) {
            map.add(new SessionToken(SessionToken.HEADER_SOURCE, HttpHeader.AUTHORIZATION, header));
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
        if (obj instanceof JSONObject) {
            extractJsonTokens((JSONObject) obj, parent, tokens);
        } else if (obj instanceof JSONArray) {
            Object[] oa = ((JSONArray) obj).toArray();
            for (int i = 0; i < oa.length; i++) {
                extractJsonTokens(oa[i], parent + "[" + i + "]", tokens);
            }
        } else if (obj instanceof String) {
            addToMap(tokens, new SessionToken(SessionToken.JSON_SOURCE, parent, (String) obj));
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
        contextVerificationMap.clear();
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

    public static void processVerificationDetails(
            Context context,
            VerificationRequestDetails details,
            VerificationDetectionScanRule rule) {

        String methodUrl =
                details.getMsg().getRequestHeader().getMethod()
                        + " "
                        + details.getMsg().getRequestHeader().getURI().toString();

        if (contextVerificationMap
                .computeIfAbsent(context.getId(), c -> Collections.synchronizedSet(new HashSet<>()))
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
            AuthUtils.authenticateAsUser(
                    bbaMethod.isDiagnostics(),
                    ssutils.getWebDriver(),
                    user,
                    bbaMethod.getLoginPageUrl(),
                    bbaMethod.getLoginPageWait(),
                    bbaMethod.getAuthenticationSteps());
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
            HttpSender authSender, User user, WebSession session, String loginUrl) {
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
                if (checkLoginLinkVerification(authSender, user, session, testUri)) {
                    // The top level URL worked :)
                    return;
                }
                testUri = new URI(loginUrl, true);
            }
            checkLoginLinkVerification(authSender, user, session, testUri);

        } catch (Exception e) {
            LOGGER.warn(
                    "Failed accessing potential login link verification URL {}, {}",
                    loginUrl,
                    e.getMessage(),
                    e);
        }
    }

    private static boolean checkLoginLinkVerification(
            HttpSender authSender, User user, WebSession session, URI testUri) {
        try {
            // Send an unauthenticated req to the test site, manually following redirects as needed
            HttpMessage msg = new HttpMessage(testUri);
            HttpSender unauthSender = new HttpSender(HttpSender.AUTHENTICATION_HELPER_INITIATOR);
            unauthSender.sendAndReceive(msg);
            historyProvider.addAuthMessageToHistory(msg);
            int count = 0;
            while (HttpStatusCode.isRedirection(msg.getResponseHeader().getStatusCode())) {
                testUri =
                        new URI(
                                msg.getResponseHeader().getHeader(HttpResponseHeader.LOCATION),
                                true);
                msg = new HttpMessage(testUri);
                unauthSender.sendAndReceive(msg);
                historyProvider.addAuthMessageToHistory(msg);
                if (count++ > 50) {
                    return false;
                }
            }

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
                        link.toString());
                return false;
            }
            LOGGER.debug(
                    "Found good login link verification req {}, contains login link {}",
                    testUri,
                    link.toString());

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
}
