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
import java.util.HashMap;
import java.util.HashSet;
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
import java.util.stream.Collectors;
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
import org.openqa.selenium.Keys;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpHeaderField;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.authhelper.BrowserBasedAuthenticationMethodType.BrowserBasedAuthenticationMethod;
import org.zaproxy.zap.authentication.AuthenticationCredentials;
import org.zaproxy.zap.authentication.AuthenticationMethod;
import org.zaproxy.zap.authentication.UsernamePasswordAuthenticationCredentials;
import org.zaproxy.zap.extension.selenium.BrowserHook;
import org.zaproxy.zap.extension.selenium.ExtensionSelenium;
import org.zaproxy.zap.extension.selenium.SeleniumScriptUtils;
import org.zaproxy.zap.extension.users.ExtensionUserManagement;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.model.SessionStructure;
import org.zaproxy.zap.users.User;
import org.zaproxy.zap.utils.Pair;
import org.zaproxy.zap.utils.Stats;

public class AuthUtils {

    public static final String AUTH_NO_USER_FIELD_STATS = "stats.auth.browser.nouserfield";
    public static final String AUTH_NO_PASSWORD_FIELD_STATS = "stats.auth.browser.nopasswordfield";
    public static final String AUTH_FOUND_FIELDS_STATS = "stats.auth.browser.foundfields";
    public static final String AUTH_SESSION_TOKEN_STATS_PREFIX = "stats.auth.sessiontoken.";
    public static final String AUTH_BROWSER_PASSED_STATS = "stats.auth.browser.passed";
    public static final String AUTH_BROWSER_FAILED_STATS = "stats.auth.browser.failed";

    public static final String[] HEADERS = {HttpHeader.AUTHORIZATION};
    public static final String[] JSON_IDS = {"accesstoken", "token"};
    private static final String[] USERNAME_FIELD_INDICATORS = {
        "email", "signinname", "uname", "user"
    };

    private static final int MIN_SESSION_COOKIE_LENGTH = 10;

    private static int MAX_NUM_RECORDS_TO_CHECK = 200;

    public static final int TIME_TO_SLEEP_IN_MSECS = 100;

    private static final Logger LOGGER = LogManager.getLogger(AuthUtils.class);

    private static AuthenticationBrowserHook browserHook;

    private static ExecutorService executorService;

    private static long timeToWaitMs = TimeUnit.SECONDS.toMillis(5);

    private static boolean demoMode;

    /**
     * These are session tokens that have been seen in responses but not yet seen in use. When they
     * are seen in use then they are removed.
     */
    private static Map<String, SessionToken> knownTokenMap = new HashMap<>();

    /**
     * The best verification request we have found for a context. There will only be a verification
     * request recorded if the user has indicated that they want ZAP to auto-detect one by: setting
     * session management to auto-detect, setting the checking strategy to "poll" but not specified
     * a URL.
     */
    private static Map<Integer, VerificationRequestDetails> contextVerifMap = new HashMap<>();

    /**
     * The best session management request we have found for a context. There will only be a
     * verification request recorded if the user has indicated that they want ZAP to auto-detect one
     * by setting session management to auto-detect.
     */
    private static Map<Integer, SessionManagementRequestDetails> contextSessionMgmtMap =
            new HashMap<>();

    public static long getTimeToWaitMs() {
        return timeToWaitMs;
    }

    public static void setTimeToWaitMs(long timeToWaitMs) {
        AuthUtils.timeToWaitMs = timeToWaitMs;
    }

    public static long getWaitLoopCount() {
        return getTimeToWaitMs() / TIME_TO_SLEEP_IN_MSECS;
    }

    static WebElement getUserField(List<WebElement> inputElements) {
        List<WebElement> filteredList =
                inputElements.stream()
                        .filter(
                                elem ->
                                        "text".equalsIgnoreCase(elem.getAttribute("type"))
                                                || "email"
                                                        .equalsIgnoreCase(
                                                                elem.getAttribute("type")))
                        .collect(Collectors.toList());

        if (!filteredList.isEmpty()) {
            if (filteredList.size() > 1) {
                LOGGER.warn("Found more than one potential user field : {}", filteredList);
                // Try to identify the best one
                for (WebElement we : filteredList) {
                    if (attributeContains(we, "id", USERNAME_FIELD_INDICATORS)
                            || attributeContains(we, "name", USERNAME_FIELD_INDICATORS)) {
                        LOGGER.debug(
                                "Choosing 'best' user field: name={} id={}",
                                we.getAttribute("name"),
                                we.getAttribute("id"));
                        return we;
                    }
                    LOGGER.debug(
                            "Not yet choosing user field: name={} id={}",
                            we.getAttribute("name"),
                            we.getAttribute("id"));
                }
            }
            LOGGER.debug(
                    "Choosing first user field: name={} id={}",
                    filteredList.get(0).getAttribute("name"),
                    filteredList.get(0).getAttribute("id"));
            return filteredList.get(0);
        }
        return null;
    }

    static boolean attributeContains(WebElement we, String attribute, String[] strings) {
        String att = we.getAttribute(attribute);
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
        for (WebElement element : inputElements) {
            if ("password".equalsIgnoreCase(element.getAttribute("type"))) {
                return element;
            }
        }
        return null;
    }

    /**
     * Authenticate as the given user, by filling in and submitting the login form
     *
     * @param wd the WebDriver controlling the browser
     * @param context the context which is being used for authentication
     * @param loginPageUrl the URL of the login page
     * @param username the username
     * @param password the password
     * @return true if the login form was successfully submitted.
     */
    public static boolean authenticateAsUser(
            WebDriver wd,
            Context context,
            String loginPageUrl,
            String username,
            String password,
            int waitInSecs) {
        wd.get(loginPageUrl);
        sleep(50);
        if (demoMode) {
            sleep(2000);
        }

        WebElement userField = null;
        WebElement pwdField = null;
        boolean userAdded = false;

        for (int i = 0; i < getWaitLoopCount(); i++) {
            List<WebElement> inputElements = wd.findElements(By.xpath("//input"));
            userField = getUserField(inputElements);
            pwdField = getPasswordField(inputElements);

            if ((userField != null || userAdded) && pwdField != null) {
                break;
            }
            if (i > 1 && userField != null && pwdField == null && !userAdded) {
                // Handle pages which require you to submit the username first
                LOGGER.debug("Submitting just user field on {}", loginPageUrl);
                userField.sendKeys(username);
                if (demoMode) {
                    sleep(2000);
                }
                userField.sendKeys(Keys.RETURN);
                if (demoMode) {
                    sleep(2000);
                }
                userAdded = true;
            }
            sleep(TIME_TO_SLEEP_IN_MSECS);
        }
        if (userField != null && pwdField != null) {
            if (!userAdded) {
                LOGGER.debug("Entering user field on {}", wd.getCurrentUrl());
                userField.sendKeys(username);
                if (demoMode) {
                    sleep(2000);
                }
            }
            try {
                LOGGER.debug("Submitting password field on {}", wd.getCurrentUrl());
                pwdField.sendKeys(password);
                if (demoMode) {
                    sleep(2000);
                }
                pwdField.sendKeys(Keys.RETURN);
            } catch (Exception e) {
                // Handle the case where the password field was present but hidden / disabled
                LOGGER.debug("Handling hidden password field on {}", wd.getCurrentUrl());
                userField.sendKeys(Keys.RETURN);
                if (demoMode) {
                    sleep(2000);
                }
                sleep(TIME_TO_SLEEP_IN_MSECS);
                pwdField.sendKeys(password);
                if (demoMode) {
                    sleep(2000);
                }
                pwdField.sendKeys(Keys.RETURN);
            }

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
                if (!incCookies && HttpHeader.COOKIE.equalsIgnoreCase(header.getName())) {
                    continue;
                }
                if (header.getValue().contains(token.getValue())) {
                    String hv =
                            header.getValue()
                                    .replace(token.getValue(), "{%" + token.getToken() + "%}");
                    list.add(new Pair<String, String>(header.getName(), hv));
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

    protected static Map<String, SessionToken> getAllTokens(HttpMessage msg) {
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

    static SessionManagementRequestDetails findSessionTokenSource(String token, int firstId) {
        ExtensionHistory extHist = AuthUtils.getExtension(ExtensionHistory.class);
        int lastId = extHist.getLastHistoryId();
        if (firstId == -1) {
            firstId = Math.max(0, lastId - MAX_NUM_RECORDS_TO_CHECK);
        }

        LOGGER.debug("Searching for session token from {} down to {} ", lastId, firstId);

        for (int i = lastId; i >= firstId; i--) {
            HistoryReference hr = extHist.getHistoryReference(i);
            if (hr != null) {
                try {
                    HttpMessage msg = hr.getHttpMessage();
                    Optional<SessionToken> es =
                            AuthUtils.getAllTokens(msg).values().stream()
                                    .filter(v -> v.getValue().equals(token))
                                    .findFirst();
                    if (es.isPresent()) {
                        AuthUtils.incStatsCounter(
                                msg.getRequestHeader().getURI(),
                                AuthUtils.AUTH_SESSION_TOKEN_STATS_PREFIX + es.get().getKey());
                        List<SessionToken> tokens = new ArrayList<>();
                        tokens.add(
                                new SessionToken(
                                        es.get().getSource(),
                                        es.get().getKey(),
                                        es.get().getValue()));
                        return new SessionManagementRequestDetails(
                                msg, tokens, Alert.CONFIDENCE_HIGH);
                    }
                } catch (Exception e) {
                    LOGGER.debug(e.getMessage(), e);
                }
            }
        }
        return null;
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
    }

    public static SessionToken getSessionToken(String value) {
        return knownTokenMap.get(value);
    }

    public static SessionToken containsSessionToken(String value) {
        Optional<Entry<String, SessionToken>> entry =
                knownTokenMap.entrySet().stream()
                        .filter(m -> value.contains(m.getKey()))
                        .findFirst();
        if (entry.isPresent()) {
            return entry.get().getValue();
        }
        return null;
    }

    public static void removeSessionToken(SessionToken token) {
        Optional<Entry<String, SessionToken>> entry =
                knownTokenMap.entrySet().stream()
                        .filter(m -> m.getValue().equals(token))
                        .findFirst();
        if (entry.isPresent()) {
            knownTokenMap.remove(token.getValue());
        }
    }

    public static void clean() {
        knownTokenMap.clear();
        contextVerifMap.clear();
        contextSessionMgmtMap.clear();
        if (executorService != null) {
            executorService.shutdown();
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
        getExecutorService().submit(new VerificationDetectionProcessor(context, details, rule));
    }

    static class AuthenticationBrowserHook implements BrowserHook {

        private BrowserBasedAuthenticationMethod bbaMethod;
        private UsernamePasswordAuthenticationCredentials userCreds;
        private Context context;

        AuthenticationBrowserHook(Context context, String userName) {
            this(context, getUser(context, userName));
        }

        AuthenticationBrowserHook(Context context, User user) {
            this.context = context;
            AuthenticationMethod method = context.getAuthenticationMethod();
            if (!(method instanceof BrowserBasedAuthenticationMethod)) {
                throw new IllegalStateException("Unsupported method " + method.getType().getName());
            }
            bbaMethod = (BrowserBasedAuthenticationMethod) method;

            AuthenticationCredentials creds = user.getAuthenticationCredentials();
            if (!(creds instanceof UsernamePasswordAuthenticationCredentials)) {
                throw new IllegalStateException(
                        "Unsupported user credentials type " + creds.getClass().getCanonicalName());
            }
            userCreds = (UsernamePasswordAuthenticationCredentials) creds;
        }

        @Override
        public void browserLaunched(SeleniumScriptUtils ssutils) {
            LOGGER.debug(
                    "AuthenticationBrowserHook - authenticating as {}", userCreds.getUsername());
            AuthUtils.authenticateAsUser(
                    ssutils.getWebDriver(),
                    context,
                    bbaMethod.getLoginPageUrl(),
                    userCreds.getUsername(),
                    userCreds.getPassword(),
                    bbaMethod.getLoginPageWait());
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
}
