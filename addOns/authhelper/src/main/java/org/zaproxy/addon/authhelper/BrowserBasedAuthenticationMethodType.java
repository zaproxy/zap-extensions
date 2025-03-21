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

import java.awt.GridBagLayout;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import net.sf.json.JSON;
import net.sf.json.JSONObject;
import org.apache.commons.configuration.Configuration;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.reflect.FieldUtils;
import org.apache.commons.lang3.reflect.MethodUtils;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openqa.selenium.WebDriver;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.db.RecordContext;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.authhelper.internal.AuthenticationStep;
import org.zaproxy.addon.authhelper.internal.AuthenticationStep.ValidationResult;
import org.zaproxy.addon.authhelper.internal.ClientSideHandler;
import org.zaproxy.addon.authhelper.internal.StepsPanel;
import org.zaproxy.addon.commonlib.internal.TotpSupport;
import org.zaproxy.addon.network.ExtensionNetwork;
import org.zaproxy.addon.network.internal.client.apachev5.HttpSenderContextApache;
import org.zaproxy.addon.network.server.HttpServerConfig;
import org.zaproxy.addon.network.server.Server;
import org.zaproxy.zap.authentication.AbstractAuthenticationMethodOptionsPanel;
import org.zaproxy.zap.authentication.AbstractCredentialsOptionsPanel;
import org.zaproxy.zap.authentication.AuthenticationCredentials;
import org.zaproxy.zap.authentication.AuthenticationHelper;
import org.zaproxy.zap.authentication.AuthenticationMethod;
import org.zaproxy.zap.authentication.AuthenticationMethodType;
import org.zaproxy.zap.authentication.UsernamePasswordAuthenticationCredentials;
import org.zaproxy.zap.authentication.UsernamePasswordAuthenticationCredentials.UsernamePasswordAuthenticationCredentialsOptionsPanel;
import org.zaproxy.zap.extension.api.ApiDynamicActionImplementor;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.extension.api.ApiResponse;
import org.zaproxy.zap.extension.api.ApiResponseSet;
import org.zaproxy.zap.extension.authentication.AuthenticationAPI;
import org.zaproxy.zap.extension.selenium.Browser;
import org.zaproxy.zap.extension.selenium.BrowserUI;
import org.zaproxy.zap.extension.selenium.BrowsersComboBoxModel;
import org.zaproxy.zap.extension.selenium.ExtensionSelenium;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.model.SessionStructure;
import org.zaproxy.zap.session.SessionManagementMethod;
import org.zaproxy.zap.session.WebSession;
import org.zaproxy.zap.users.User;
import org.zaproxy.zap.utils.ApiUtils;
import org.zaproxy.zap.utils.Stats;
import org.zaproxy.zap.utils.ZapNumberSpinner;
import org.zaproxy.zap.utils.ZapTextField;
import org.zaproxy.zap.view.LayoutHelper;
import org.zaproxy.zap.view.NodeSelectDialog;

public class BrowserBasedAuthenticationMethodType extends AuthenticationMethodType {

    private static final int METHOD_IDENTIFIER = 6;

    private static final String API_METHOD_NAME = "browserBasedAuthentication";

    private static final String CONTEXT_CONFIG_AUTH_BROWSER =
            AuthenticationMethod.CONTEXT_CONFIG_AUTH + ".browser";
    private static final String CONTEXT_CONFIG_AUTH_BROWSER_LOGINPAGEURL =
            CONTEXT_CONFIG_AUTH_BROWSER + ".loginpageurl";
    private static final String CONTEXT_CONFIG_AUTH_BROWSER_LOGINPAGEWAIT =
            CONTEXT_CONFIG_AUTH_BROWSER + ".loginpagewait";
    private static final String CONTEXT_CONFIG_AUTH_BROWSER_BROWSERID =
            CONTEXT_CONFIG_AUTH_BROWSER + ".browserid";
    private static final String CONTEXT_CONFIG_AUTH_BROWSER_STEP =
            CONTEXT_CONFIG_AUTH_BROWSER + ".steps.step";

    /* API related constants and methods. */
    private static final String PARAM_BROWSER_ID = "browserId";
    private static final String PARAM_LOGIN_PAGE_URL = "loginPageUrl";
    private static final String PARAM_LOGIN_PAGE_WAIT = "loginPageWait";

    public static final String DEFAULT_BROWSER_ID = Browser.FIREFOX_HEADLESS.getId();
    private static final int DEFAULT_PAGE_WAIT = 5;

    private static final Logger LOGGER =
            LogManager.getLogger(BrowserBasedAuthenticationMethodType.class);

    private String proxyHost = "localhost";
    private int proxyPort;
    private Server proxy;

    private ClientSideHandler handler;

    private static List<Server> proxies = new ArrayList<>();

    private HttpSender httpSender;

    public BrowserBasedAuthenticationMethodType() {}

    public BrowserBasedAuthenticationMethodType(HttpSender httpSender) {
        this.httpSender = httpSender;
    }

    private Server getProxy(User user) {
        if (proxy == null) {
            ExtensionNetwork extNet = AuthUtils.getExtension(ExtensionNetwork.class);
            handler = new ClientSideHandler(user);
            proxy =
                    extNet.createHttpServer(
                            HttpServerConfig.builder()
                                    .setHttpMessageHandler(handler)
                                    .setHttpSender(getHttpSender())
                                    .setServeZapApi(true)
                                    .build());
        }
        return proxy;
    }

    public Object getCookieStore() {
        try {
            HttpSender temp = getHttpSender();
            Object obj = MethodUtils.invokeMethod(temp, true, "getContext");

            if (obj instanceof HttpSenderContextApache) {
                return FieldUtils.readField(
                        HttpSenderContextApache.class.getDeclaredField("localCookieStore"),
                        (HttpSenderContextApache) obj,
                        true);
            }
        } catch (Exception e) {
            LOGGER.error(
                    "Failed get {} private field: {}",
                    getHttpSender().getClass().getCanonicalName(),
                    "ctx",
                    e);
        }
        return null;
    }

    private synchronized HttpSender getHttpSender() {
        if (httpSender == null) {
            httpSender = new HttpSender(HttpSender.AUTHENTICATION_HELPER_INITIATOR);
            httpSender.setUseGlobalState(false);
        }
        return httpSender;
    }

    public static void stopProxies() {
        proxies.forEach(
                p -> {
                    try {
                        p.stop();
                    } catch (IOException e) {
                        // Ignore
                    }
                });
        proxies.clear();
    }

    public class BrowserBasedAuthenticationMethod extends AuthenticationMethod {

        private boolean diagnostics;
        private String loginPageUrl;
        private String browserId = DEFAULT_BROWSER_ID;
        private int loginPageWait = DEFAULT_PAGE_WAIT;
        private List<AuthenticationStep> authenticationSteps = List.of();

        public BrowserBasedAuthenticationMethod() {}

        public BrowserBasedAuthenticationMethod(BrowserBasedAuthenticationMethod method) {
            diagnostics = method.diagnostics;
            this.loginPageUrl = method.loginPageUrl;
            this.browserId = method.browserId;
            this.loginPageWait = method.loginPageWait;
            authenticationSteps =
                    method.getAuthenticationSteps().stream().map(AuthenticationStep::new).toList();
        }

        @Override
        public boolean isConfigured() {
            return loginPageUrl != null;
        }

        @Override
        protected AuthenticationMethod duplicate() {
            return new BrowserBasedAuthenticationMethod(this);
        }

        @Override
        public AuthenticationCredentials createAuthenticationCredentials() {
            return TotpSupport.createUsernamePasswordAuthenticationCredentials();
        }

        @Override
        public AuthenticationMethodType getType() {
            return new BrowserBasedAuthenticationMethodType(httpSender);
        }

        public boolean isDiagnostics() {
            return diagnostics;
        }

        public void setDiagnostics(boolean diagnostics) {
            this.diagnostics = diagnostics;
        }

        public String getLoginPageUrl() {
            return loginPageUrl;
        }

        public void setLoginPageUrl(String loginPageUrl) {
            this.loginPageUrl = loginPageUrl;
        }

        public void setBrowserId(String browserId) {
            if (!StringUtils.isEmpty(browserId)) {
                this.browserId = browserId;
            }
        }

        public String getBrowserId() {
            return this.browserId;
        }

        public int getLoginPageWait() {
            return loginPageWait;
        }

        public void setLoginPageWait(int loginPageWait) {
            this.loginPageWait = loginPageWait;
        }

        public List<AuthenticationStep> getAuthenticationSteps() {
            return authenticationSteps;
        }

        public void setAuthenticationSteps(List<AuthenticationStep> authenticationSteps) {
            this.authenticationSteps =
                    authenticationSteps == null ? List.of() : authenticationSteps;
        }

        @Override
        public WebSession authenticate(
                SessionManagementMethod sessionManagementMethod,
                AuthenticationCredentials credentials,
                User user)
                throws UnsupportedAuthenticationCredentialsException {

            if (user.getAuthenticationCredentials() != credentials) {
                throw new UnsupportedAuthenticationCredentialsException(
                        "Provided credentials do not match that of the user.");
            }

            try (AuthenticationDiagnostics diags =
                    new AuthenticationDiagnostics(
                            diagnostics, getName(), user.getContext().getName(), user.getName())) {
                return authenticateImpl(diags, sessionManagementMethod, user);
            }
        }

        private WebSession authenticateImpl(
                AuthenticationDiagnostics diags,
                SessionManagementMethod sessionManagementMethod,
                User user) {
            if (handler != null) {
                handler.resetAuthMsg();
            }
            if (this.loginPageWait > 0) {
                AuthUtils.setTimeToWaitMs(TimeUnit.SECONDS.toMillis(loginPageWait));
            }

            ExtensionSelenium extSel =
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionSelenium.class);

            try {
                proxyPort = getProxy(user).start(proxyHost, 0);

                WebDriver wd = null;
                try {
                    wd =
                            extSel.getWebDriver(
                                    HttpSender.AUTHENTICATION_INITIATOR,
                                    this.browserId,
                                    proxyHost,
                                    proxyPort);

                    if (AuthUtils.authenticateAsUserImpl(
                            diags, wd, user, loginPageUrl, loginPageWait, authenticationSteps)) {
                        // Wait until the authentication request is identified
                        for (int i = 0; i < AuthUtils.getWaitLoopCount(); i++) {
                            if (handler.getAuthMsg() != null) {
                                break;
                            }
                            AuthUtils.sleep(AuthUtils.TIME_TO_SLEEP_IN_MSECS);
                        }
                    }
                } finally {
                    if (wd != null) {
                        wd.quit();
                    }
                }

                HttpMessage authMsg = handler.getAuthMsg();
                if (authMsg != null) {
                    // Update the session as it may have changed
                    for (int i = 0; i < AuthUtils.getWaitLoopCount(); i++) {
                        // The session management method is set via a pscan rule, so make sure it is
                        // set
                        LOGGER.debug(
                                "Update session? {}",
                                sessionManagementMethod.getClass().getCanonicalName());
                        if (!(sessionManagementMethod
                                instanceof
                                AutoDetectSessionManagementMethodType
                                        .AutoDetectSessionManagementMethod)) {
                            break;
                        }
                        sessionManagementMethod = user.getContext().getSessionManagementMethod();
                        AuthUtils.sleep(AuthUtils.TIME_TO_SLEEP_IN_MSECS);
                    }
                    WebSession session = sessionManagementMethod.extractWebSession(authMsg);
                    if (session != null) {
                        diags.recordStep(
                                authMsg,
                                Constant.messages.getString(
                                        "authhelper.auth.method.diags.steps.sessionupdate"));
                        LOGGER.info(
                                "Updating session management method {} with session {}",
                                sessionManagementMethod.getClass().getCanonicalName(),
                                session.getClass().getCanonicalName());
                        user.setAuthenticatedSession(session);
                    }

                    AuthUtils.checkLoginLinkVerification(httpSender, user, session, loginPageUrl);

                    if (this.isAuthenticated(authMsg, user, true)) {
                        diags.recordStep(
                                authMsg,
                                Constant.messages.getString(
                                        "authhelper.auth.method.diags.steps.authenticated"));
                        // Let the user know it worked
                        AuthenticationHelper.notifyOutputAuthSuccessful(authMsg);
                        user.getAuthenticationState().setLastAuthFailure("");
                    } else {
                        diags.recordStep(
                                authMsg,
                                Constant.messages.getString(
                                        "authhelper.auth.method.diags.steps.unauthenticated"));
                        // Let the user know it failed
                        AuthenticationHelper.notifyOutputAuthFailure(authMsg);
                    }
                    return session;
                }

            } catch (IOException e) {
                LOGGER.error(e.getMessage(), e);
            }

            // Code based on Authentication.notifyOutputAuthFailure
            try {
                Stats.incCounter(
                        SessionStructure.getHostName(new URI(this.loginPageUrl, true)),
                        AuthenticationHelper.AUTH_FAILURE_STATS);
            } catch (URIException e) {
                // Ignore
            }
            // Let the user know it failed
            AuthUtils.logUserMessage(
                    Level.INFO,
                    Constant.messages.getString("authentication.output.failure", this.loginPageUrl)
                            + "\n");

            HttpMessage fallbackMsg = handler.getFallbackMsg();
            diags.recordStep(
                    fallbackMsg,
                    Constant.messages.getString("authhelper.auth.method.diags.steps.fallback"));
            // We don't expect this to work, but it will prevent some NPEs
            return sessionManagementMethod.extractWebSession(fallbackMsg);
        }

        @Override
        public ApiResponse getApiResponseRepresentation() {
            Map<String, Object> values = new HashMap<>();
            values.put(PARAM_LOGIN_PAGE_URL, loginPageUrl);
            values.put(PARAM_BROWSER_ID, browserId);
            values.put(PARAM_LOGIN_PAGE_WAIT, loginPageWait);
            return new AuthMethodApiResponseRepresentation<>(values);
        }

        @Override
        public void replaceUserDataInPollRequest(HttpMessage msg, User user) {
            user.processMessageToMatchAuthenticatedSession(msg);
        }

        public void toMap(Map<String, Object> map) {
            map.put(
                    "steps",
                    authenticationSteps.stream().sorted().map(AuthenticationStep::toMap).toList());
        }

        @SuppressWarnings({"unchecked", "rawtypes"})
        public void fromMap(Map<String, Object> map) {
            Object object = map.get("steps");
            if (object instanceof List steps) {
                List<AuthenticationStep> loadedSteps = new ArrayList<>();
                steps.forEach(
                        e -> {
                            if (!(e instanceof Map)) {
                                return;
                            }

                            AuthenticationStep step =
                                    AuthenticationStep.fromMap((Map<String, Object>) e);
                            if (AuthenticationStep.validate(null, step, loadedSteps)
                                    == ValidationResult.VALID) {
                                step.setOrder(loadedSteps.size() + 1);
                                loadedSteps.add(step);
                            }
                        });

                authenticationSteps = loadedSteps;
            }
        }
    }

    @Override
    public BrowserBasedAuthenticationMethod createAuthenticationMethod(int contextId) {
        return new BrowserBasedAuthenticationMethod();
    }

    @Override
    public String getName() {
        return Constant.messages.getString("authhelper.auth.method.browser.name");
    }

    @Override
    public int getUniqueIdentifier() {
        return METHOD_IDENTIFIER;
    }

    @Override
    public AbstractAuthenticationMethodOptionsPanel buildOptionsPanel(Context uiSharedContext) {
        return new BrowserBasedAuthenticationMethodOptionsPanel(uiSharedContext);
    }

    @Override
    public boolean hasOptionsPanel() {
        return true;
    }

    @Override
    public AbstractCredentialsOptionsPanel<? extends AuthenticationCredentials>
            buildCredentialsOptionsPanel(
                    AuthenticationCredentials credentials, Context uiSharedContext) {
        return new UsernamePasswordAuthenticationCredentialsOptionsPanel(
                (UsernamePasswordAuthenticationCredentials) credentials);
    }

    @Override
    public boolean hasCredentialsOptionsPanel() {
        return true;
    }

    @Override
    public boolean isTypeForMethod(AuthenticationMethod method) {
        return method instanceof BrowserBasedAuthenticationMethod;
    }

    @Override
    public void hook(ExtensionHook extensionHook) {}

    @Override
    public AuthenticationMethod loadMethodFromSession(Session session, int contextId)
            throws DatabaseException {
        BrowserBasedAuthenticationMethod method = createAuthenticationMethod(contextId);
        method.setLoginPageUrl(
                session.getContextDataString(
                        contextId, RecordContext.TYPE_AUTH_METHOD_FIELD_1, ""));
        method.setBrowserId(
                session.getContextDataString(
                        contextId, RecordContext.TYPE_AUTH_METHOD_FIELD_2, DEFAULT_BROWSER_ID));
        String waitStr =
                session.getContextDataString(contextId, RecordContext.TYPE_AUTH_METHOD_FIELD_3, "");
        if (!StringUtils.isEmpty(waitStr)) {
            try {
                method.setLoginPageWait(Integer.parseInt(waitStr));
            } catch (NumberFormatException e) {
                // Ignore
            }
        }

        try {
            List<AuthenticationStep> loaded =
                    session
                            .getContextDataStrings(
                                    contextId, RecordContext.TYPE_AUTH_METHOD_FIELD_4)
                            .stream()
                            .map(AuthenticationStep::decode)
                            .filter(Objects::nonNull)
                            .toList();
            method.setAuthenticationSteps(loaded);
        } catch (Exception e) {
            LOGGER.error("An error occurred while loading the data:", e);
        }

        return method;
    }

    @Override
    public void persistMethodToSession(
            Session session, int contextId, AuthenticationMethod authMethod)
            throws DatabaseException {
        if (!(authMethod instanceof BrowserBasedAuthenticationMethod)) {
            throw new UnsupportedAuthenticationMethodException(
                    "Browser based authentication type only supports: "
                            + BrowserBasedAuthenticationMethod.class);
        }

        BrowserBasedAuthenticationMethod method = (BrowserBasedAuthenticationMethod) authMethod;
        session.setContextData(
                contextId, RecordContext.TYPE_AUTH_METHOD_FIELD_1, method.loginPageUrl);
        session.setContextData(contextId, RecordContext.TYPE_AUTH_METHOD_FIELD_2, method.browserId);
        session.setContextData(
                contextId,
                RecordContext.TYPE_AUTH_METHOD_FIELD_3,
                Integer.toString(method.loginPageWait));

        try {
            List<String> data =
                    method.authenticationSteps.stream().map(AuthenticationStep::encode).toList();
            session.setContextData(contextId, RecordContext.TYPE_AUTH_METHOD_FIELD_4, data);
        } catch (Exception e) {
            LOGGER.error("An error occurred while persisting the data:", e);
        }
    }

    @Override
    public void exportData(Configuration config, AuthenticationMethod authMethod) {
        if (!(authMethod instanceof BrowserBasedAuthenticationMethod)) {
            throw new UnsupportedAuthenticationMethodException(
                    "Browser based authentication type only supports: "
                            + BrowserBasedAuthenticationMethod.class);
        }

        BrowserBasedAuthenticationMethod method = (BrowserBasedAuthenticationMethod) authMethod;

        config.setProperty(CONTEXT_CONFIG_AUTH_BROWSER_LOGINPAGEURL, method.loginPageUrl);
        config.setProperty(CONTEXT_CONFIG_AUTH_BROWSER_BROWSERID, method.browserId);
        config.setProperty(CONTEXT_CONFIG_AUTH_BROWSER_LOGINPAGEWAIT, method.loginPageWait);

        method.authenticationSteps.stream()
                .map(AuthenticationStep::encode)
                .forEach(e -> config.addProperty(CONTEXT_CONFIG_AUTH_BROWSER_STEP, e));
    }

    @Override
    public void importData(Configuration config, AuthenticationMethod authMethod)
            throws ConfigurationException {
        if (!(authMethod instanceof BrowserBasedAuthenticationMethod)) {
            throw new UnsupportedAuthenticationMethodException(
                    "Browser based authentication type only supports: "
                            + BrowserBasedAuthenticationMethod.class);
        }

        BrowserBasedAuthenticationMethod method = (BrowserBasedAuthenticationMethod) authMethod;

        try {
            method.setLoginPageUrl(config.getString(CONTEXT_CONFIG_AUTH_BROWSER_LOGINPAGEURL));
        } catch (Exception e) {
            throw new ConfigurationException(e);
        }
        try {
            method.setBrowserId(config.getString(CONTEXT_CONFIG_AUTH_BROWSER_BROWSERID));
        } catch (Exception e) {
            throw new ConfigurationException(e);
        }
        try {
            method.setLoginPageWait(config.getInt(CONTEXT_CONFIG_AUTH_BROWSER_LOGINPAGEWAIT));
        } catch (Exception e) {
            throw new ConfigurationException(e);
        }

        try {
            List<AuthenticationStep> steps =
                    config.getList(CONTEXT_CONFIG_AUTH_BROWSER_STEP).stream()
                            .map(Object::toString)
                            .map(AuthenticationStep::decode)
                            .filter(Objects::nonNull)
                            .toList();
            method.setAuthenticationSteps(steps);
        } catch (Exception e) {
            throw new ConfigurationException(e);
        }
    }

    @Override
    public UsernamePasswordAuthenticationCredentials createAuthenticationCredentials() {
        return new UsernamePasswordAuthenticationCredentials();
    }

    @Override
    public Class<UsernamePasswordAuthenticationCredentials> getAuthenticationCredentialsType() {
        return UsernamePasswordAuthenticationCredentials.class;
    }

    @Override
    public ApiDynamicActionImplementor getSetMethodForContextApiAction() {
        String[] mandatoryParamNames = new String[] {PARAM_LOGIN_PAGE_URL};
        String[] optionalParamNames = new String[] {PARAM_BROWSER_ID, PARAM_LOGIN_PAGE_WAIT};
        return new ApiDynamicActionImplementor(
                API_METHOD_NAME, mandatoryParamNames, optionalParamNames) {

            @Override
            public void handleAction(JSONObject params) throws ApiException {
                Context context =
                        ApiUtils.getContextByParamId(params, AuthenticationAPI.PARAM_CONTEXT_ID);

                // Set the method
                BrowserBasedAuthenticationMethod method =
                        createAuthenticationMethod(context.getId());
                try {
                    method.setLoginPageUrl(
                            ApiUtils.getNonEmptyStringParam(params, PARAM_LOGIN_PAGE_URL));

                    String browserId = ApiUtils.getOptionalStringParam(params, PARAM_BROWSER_ID);
                    if (!StringUtils.isEmpty(browserId)) {
                        method.setBrowserId(browserId);
                    }

                    String loginPageWaitStr =
                            ApiUtils.getOptionalStringParam(params, PARAM_LOGIN_PAGE_WAIT);
                    if (!StringUtils.isEmpty(loginPageWaitStr)) {
                        method.setLoginPageWait(Integer.parseInt(loginPageWaitStr));
                    }

                } catch (ApiException e) {
                    throw e;
                } catch (Exception e) {
                    throw new ApiException(ApiException.Type.INTERNAL_ERROR, e.getMessage());
                }

                context.setAuthenticationMethod(method);
            }
        };
    }

    @Override
    public ApiDynamicActionImplementor getSetCredentialsForUserApiAction() {
        return UsernamePasswordAuthenticationCredentials.getSetCredentialsForUserApiAction(this);
    }

    /** The Options Panel used for configuring a {@link BrowserBasedAuthenticationMethod}. */
    @SuppressWarnings("serial")
    protected class BrowserBasedAuthenticationMethodOptionsPanel
            extends AbstractAuthenticationMethodOptionsPanel {

        private static final long serialVersionUID = 1L;
        private BrowserBasedAuthenticationMethod authenticationMethod;

        private ZapTextField loginUrlField;
        private JComboBox<BrowserUI> browserCombo;
        private ZapNumberSpinner loginUrlWait;
        private StepsPanel stepsPanel;

        public BrowserBasedAuthenticationMethodOptionsPanel(Context context) {
            this.setLayout(new GridBagLayout());

            this.loginUrlField = new ZapTextField();

            JButton selectButton = new JButton(Constant.messages.getString("all.button.select"));
            selectButton.setIcon(
                    new ImageIcon(View.class.getResource("/resource/icon/16/094.png"))); // Globe

            // Add behaviour for Node Select dialog
            selectButton.addActionListener(
                    new java.awt.event.ActionListener() {
                        @Override
                        public void actionPerformed(java.awt.event.ActionEvent e) {
                            NodeSelectDialog nsd =
                                    new NodeSelectDialog(View.getSingleton().getMainFrame());
                            // Try to pre-select the node according to what has been inserted in the
                            // fields
                            SiteNode node = null;
                            if (loginUrlField.getText().trim().length() > 0)
                                try {
                                    node =
                                            Model.getSingleton()
                                                    .getSession()
                                                    .getSiteTree()
                                                    .findNode(
                                                            new URI(
                                                                    loginUrlField.getText(),
                                                                    false));
                                } catch (Exception e2) {
                                    // Ignore. It means we could not properly get a node for the
                                    // existing
                                    // value and does not have any harmful effects
                                }

                            // Show the dialog and wait for input
                            node = nsd.showDialog(node);
                            if (node != null && node.getHistoryReference() != null) {
                                try {
                                    LOGGER.debug(
                                            "Selected Browser Based Auth Login URL via dialog: {}",
                                            node.getHistoryReference().getURI());

                                    loginUrlField.setText(
                                            node.getHistoryReference().getURI().toString());
                                } catch (Exception e1) {
                                    LOGGER.error(e1.getMessage(), e1);
                                }
                            }
                        }
                    });

            JLabel urlSelectLabel =
                    new JLabel(
                            Constant.messages.getString(
                                    "authhelper.auth.method.browser.label.loginUrl"));
            urlSelectLabel.setLabelFor(loginUrlField);
            this.add(urlSelectLabel, LayoutHelper.getGBC(0, 0, 2, 1.0d, 0.0d));

            JPanel urlSelectPanel = new JPanel(new GridBagLayout());
            urlSelectPanel.add(this.loginUrlField, LayoutHelper.getGBC(0, 0, 1, 1.0D));
            urlSelectPanel.add(selectButton, LayoutHelper.getGBC(1, 0, 1, 0.0D));

            this.add(urlSelectPanel, LayoutHelper.getGBC(0, 1, 2, 1.0d, 0.0d));

            ExtensionSelenium extSel =
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionSelenium.class);

            browserCombo = new JComboBox<>(extSel.createBrowsersComboBoxModel());

            JLabel browserSelectLabel =
                    new JLabel(
                            Constant.messages.getString(
                                    "authhelper.auth.method.browser.label.browser"));
            browserSelectLabel.setLabelFor(browserCombo);

            this.add(browserSelectLabel, LayoutHelper.getGBC(0, 2, 1, 1.0d, 0.0d));
            this.add(browserCombo, LayoutHelper.getGBC(1, 2, 1, 1.0d, 0.0d));

            loginUrlWait = new ZapNumberSpinner(1, DEFAULT_PAGE_WAIT, Integer.MAX_VALUE);
            JLabel loginWaitLabel =
                    new JLabel(
                            Constant.messages.getString(
                                    "authhelper.auth.method.browser.label.loginWait"));
            loginWaitLabel.setLabelFor(loginUrlWait);
            this.add(loginWaitLabel, LayoutHelper.getGBC(0, 3, 1, 1.0d, 0.0d));
            this.add(loginUrlWait, LayoutHelper.getGBC(1, 3, 1, 1.0d, 0.0d));

            stepsPanel = new StepsPanel(View.getSingleton().getSessionDialog(), false);
            add(stepsPanel.getPanel(), LayoutHelper.getGBC(0, 4, 2, 1.0d, 1.0d));
        }

        @Override
        public void validateFields() throws IllegalStateException {
            if (StringUtils.isEmpty(loginUrlField.getText())) {
                loginUrlField.requestFocusInWindow();
                throw new IllegalStateException(
                        Constant.messages.getString(
                                "authentication.method.pb.dialog.error.url.text"));
            }
        }

        @Override
        public void saveMethod() {
            getMethod().setLoginPageUrl(loginUrlField.getText());
            getMethod()
                    .setBrowserId(
                            ((BrowserUI) browserCombo.getSelectedItem()).getBrowser().getId());
            getMethod().setLoginPageWait(loginUrlWait.getValue());
            authenticationMethod.setAuthenticationSteps(stepsPanel.getSteps());
        }

        @Override
        public void bindMethod(AuthenticationMethod method)
                throws UnsupportedAuthenticationMethodException {
            this.authenticationMethod = (BrowserBasedAuthenticationMethod) method;
            this.loginUrlField.setText(authenticationMethod.getLoginPageUrl());
            ((BrowsersComboBoxModel) this.browserCombo.getModel())
                    .setSelectedBrowser(this.authenticationMethod.getBrowserId());
            this.loginUrlWait.setValue(authenticationMethod.getLoginPageWait());
            stepsPanel.setSteps(authenticationMethod.getAuthenticationSteps());
        }

        @Override
        public BrowserBasedAuthenticationMethod getMethod() {
            return this.authenticationMethod;
        }
    }

    /*
     * Copied from org.zaproxy.zap.authentication.AuthenticationMethod
     */
    static class AuthMethodApiResponseRepresentation<T> extends ApiResponseSet<T> {

        public AuthMethodApiResponseRepresentation(Map<String, T> values) {
            super("method", values);
        }

        @Override
        public JSON toJSON() {
            JSONObject response = new JSONObject();
            response.put(getName(), super.toJSON());
            return response;
        }
    }
}
