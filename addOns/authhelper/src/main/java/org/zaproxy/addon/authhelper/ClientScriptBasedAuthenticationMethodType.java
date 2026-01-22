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
package org.zaproxy.addon.authhelper;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import org.apache.commons.configuration.Configuration;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openqa.selenium.WebDriver;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.db.RecordContext;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.authhelper.internal.ClientSideHandler;
import org.zaproxy.addon.authhelper.internal.ZestAuthRunner;
import org.zaproxy.addon.commonlib.internal.TotpSupport;
import org.zaproxy.addon.network.ExtensionNetwork;
import org.zaproxy.addon.network.server.HttpMessageHandler;
import org.zaproxy.addon.network.server.ServerInfo;
import org.zaproxy.zap.authentication.AbstractAuthenticationMethodOptionsPanel;
import org.zaproxy.zap.authentication.AuthenticationCredentials;
import org.zaproxy.zap.authentication.AuthenticationHelper;
import org.zaproxy.zap.authentication.AuthenticationMethod;
import org.zaproxy.zap.authentication.AuthenticationMethodType;
import org.zaproxy.zap.authentication.AuthenticationMethodType.UnsupportedAuthenticationMethodException;
import org.zaproxy.zap.authentication.GenericAuthenticationCredentials;
import org.zaproxy.zap.authentication.ScriptBasedAuthenticationMethodType;
import org.zaproxy.zap.authentication.ScriptBasedAuthenticationMethodType.ScriptBasedAuthenticationMethod;
import org.zaproxy.zap.extension.api.ApiDynamicActionImplementor;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.selenium.ClientAuthenticator;
import org.zaproxy.zap.extension.zest.ZestAuthenticationRunner;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.session.SessionManagementMethod;
import org.zaproxy.zap.session.WebSession;
import org.zaproxy.zap.users.User;
import org.zaproxy.zap.utils.ZapNumberSpinner;
import org.zaproxy.zap.view.LayoutHelper;
import org.zaproxy.zest.core.v1.ZestActionSleep;
import org.zaproxy.zest.core.v1.ZestClientLaunch;
import org.zaproxy.zest.core.v1.ZestClientWindowClose;
import org.zaproxy.zest.core.v1.ZestScript;
import org.zaproxy.zest.core.v1.ZestStatement;

public class ClientScriptBasedAuthenticationMethodType extends ScriptBasedAuthenticationMethodType {

    public static final int METHOD_IDENTIFIER = 8;
    private static final String API_METHOD_NAME = "clientScriptBasedAuthentication";

    private static final Logger LOGGER =
            LogManager.getLogger(ClientScriptBasedAuthenticationMethodType.class);

    private static final String CONTEXT_CONFIG_LOGIN_PAGE_WAIT =
            CONTEXT_CONFIG_AUTH_SCRIPT + ".loginpagewait";

    private static final String CONTEXT_CONFIG_MIN_WAIT_FOR =
            CONTEXT_CONFIG_AUTH_SCRIPT + ".minwaitfor";

    private static final int DEFAULT_PAGE_WAIT = 5;
    private static final int DEFAULT_MIN_WAIT_FOR = 0;

    private ExtensionScript extensionScript;

    private ClientSideHandler handler;

    public ClientScriptBasedAuthenticationMethodType() {}

    private HttpMessageHandler getHandler(User user) {
        if (handler == null) {
            handler = new ClientSideHandler(user);
        }
        return handler;
    }

    @Override
    public String getName() {
        return Constant.messages.getString("authhelper.auth.method.clientscript.name");
    }

    @Override
    public int getUniqueIdentifier() {
        return METHOD_IDENTIFIER;
    }

    @Override
    public ClientScriptBasedAuthenticationMethod createAuthenticationMethod(int contextId) {
        return new ClientScriptBasedAuthenticationMethod();
    }

    @Override
    public void persistMethodToSession(
            Session session, int contextId, AuthenticationMethod authMethod)
            throws UnsupportedAuthenticationMethodException, DatabaseException {
        super.persistMethodToSession(session, contextId, authMethod);

        ClientScriptBasedAuthenticationMethod method =
                (ClientScriptBasedAuthenticationMethod) authMethod;
        session.setContextData(
                contextId,
                RecordContext.TYPE_AUTH_METHOD_FIELD_3,
                Integer.toString(method.getLoginPageWait()));
        session.setContextData(
                contextId,
                RecordContext.TYPE_AUTH_METHOD_FIELD_4,
                Integer.toString(method.getMinWaitFor()));
    }

    @Override
    protected void validateAuthenticationMethod(AuthenticationMethod method) {
        if (!(method instanceof ClientScriptBasedAuthenticationMethod)) {
            throw new UnsupportedAuthenticationMethodException(
                    "Client script based authentication type only supports: "
                            + ClientScriptBasedAuthenticationMethod.class.getName());
        }
    }

    @Override
    public ScriptBasedAuthenticationMethod loadMethodFromSession(Session session, int contextId)
            throws DatabaseException {
        ClientScriptBasedAuthenticationMethod method =
                (ClientScriptBasedAuthenticationMethod)
                        super.loadMethodFromSession(session, contextId);

        String waitStr =
                session.getContextDataString(contextId, RecordContext.TYPE_AUTH_METHOD_FIELD_3, "");
        if (!StringUtils.isEmpty(waitStr)) {
            try {
                method.setLoginPageWait(Integer.parseInt(waitStr));
            } catch (NumberFormatException ignore) {
            }
        }
        String minWaitStr =
                session.getContextDataString(contextId, RecordContext.TYPE_AUTH_METHOD_FIELD_4, "");
        if (!StringUtils.isEmpty(minWaitStr)) {
            try {
                method.setMinWaitFor(Integer.parseInt(minWaitStr));
            } catch (NumberFormatException ignore) {
            }
        }
        return method;
    }

    @Override
    public boolean isTypeForMethod(AuthenticationMethod method) {
        return method != null
                && ClientScriptBasedAuthenticationMethod.class.equals(method.getClass());
    }

    @Override
    public AbstractAuthenticationMethodOptionsPanel buildOptionsPanel(Context uiSharedContext) {
        return new ClientScriptBasedAuthenticationMethodOptionsPanel();
    }

    public class ClientScriptBasedAuthenticationMethod extends ScriptBasedAuthenticationMethod
            implements ClientAuthenticator {

        private int loginPageWait = DEFAULT_PAGE_WAIT;
        private int minWaitFor;

        private boolean diagnostics;

        public void setDiagnostics(boolean diagnostics) {
            this.diagnostics = diagnostics;
        }

        public boolean isDiagnostics() {
            return diagnostics;
        }

        public void setLoginPageWait(int loginPageWait) {
            this.loginPageWait = loginPageWait;
        }

        public int getLoginPageWait() {
            return loginPageWait;
        }

        public int getMinWaitFor() {
            return minWaitFor;
        }

        public void setMinWaitFor(int minWaitFor) {
            this.minWaitFor = minWaitFor;
        }

        public void setScriptWrapper(ScriptWrapper wrapper) {
            super.setScript(wrapper);
        }

        @Override
        public void setParamValues(Map<String, String> map) {
            super.setParamValues(map);
        }

        @Override
        public AuthenticationMethod duplicate() {
            ClientScriptBasedAuthenticationMethod method =
                    (ClientScriptBasedAuthenticationMethod) super.duplicate();
            method.diagnostics = diagnostics;
            method.loginPageWait = loginPageWait;
            method.minWaitFor = minWaitFor;
            return method;
        }

        @Override
        protected ScriptBasedAuthenticationMethod createInstance() {
            return new ClientScriptBasedAuthenticationMethod();
        }

        @Override
        public AuthenticationCredentials createAuthenticationCredentials() {
            return TotpSupport.createGenericAuthenticationCredentials(getCredentialsParamNames());
        }

        @Override
        public AuthenticationMethodType getType() {
            return new ClientScriptBasedAuthenticationMethodType();
        }

        /**
         * Executes the Zest authentication script using the provided runner.
         *
         * @param runner the ZestAuthRunner configured with proxy and WebDriver
         * @param user the user to authenticate
         * @throws Exception if an error occurs during script execution
         */
        private void executeZestAuthScript(ZestAuthRunner runner, User user) throws Exception {
            Map<String, String> paramsValues = new HashMap<>();
            ZestAuthenticationRunner.copyCredentials(
                    (GenericAuthenticationCredentials) user.getAuthenticationCredentials(),
                    paramsValues);

            ZestScript zestScript = getZestScript();
            AuthUtils.setMinWaitFor(zestScript, minWaitFor);
            runner.setup(user, zestScript);
            runner.run(zestScript, paramsValues);

            int sleepTime = loginPageWait;
            if (sleepTime > 0) {
                AuthUtils.sleep(TimeUnit.SECONDS.toMillis(sleepTime));
            }
        }

        @Override
        public boolean authenticate(WebDriver webDriver, User user) {
            ZestScript zestScript = getZestScript();
            if (zestScript == null) {
                LOGGER.warn("No Zest script configured for client script authentication");
                return false;
            }
            try {
                ZestAuthRunner runner = new ZestAuthRunner();
                // Always proxy via ZAP
                ServerInfo mainProxyInfo =
                        AuthUtils.getExtension(ExtensionNetwork.class).getMainProxyServerInfo();
                runner.setProxy(mainProxyInfo.getAddress(), mainProxyInfo.getPort());
                runner.setWebDriver(webDriver);

                executeZestAuthScript(runner, user);
                return true;
            } catch (Exception e) {
                LOGGER.warn(
                        "An error occurred while trying to execute the Client Script Authentication script: {}",
                        e.getMessage(),
                        e);
                return false;
            }
        }

        public ZestScript getZestScript() {
            AuthenticationScript authScript = getAuthenticationScript(getScript());

            if (authScript == null) {
                LOGGER.debug("Failed to get ZestScript - no suitable interface");
                return null;
            }

            if (authScript instanceof ZestAuthenticationRunner zestScript) {
                return zestScript.getScript().getZestScript();
            }
            LOGGER.debug(
                    "Failed to get ZestScript - authScript of right type {}",
                    authScript.getClass().getCanonicalName());
            return null;
        }

        private boolean hasBrowserLaunch(ZestScript zestScript) {
            // Check top level statements only.
            return zestScript.getStatements().stream().anyMatch(ZestClientLaunch.class::isInstance);
        }

        private void removeCloseStatements(ZestScript zestScript) {
            for (int i = 0; i < zestScript.getStatements().size(); i++) {
                ZestStatement stmt = zestScript.getStatements().get(i);
                if (stmt instanceof ZestClientWindowClose) {
                    zestScript.getStatements().remove(i);
                    i -= 1;
                }
            }
        }

        @Override
        public WebSession authenticate(
                SessionManagementMethod sessionManagementMethod,
                AuthenticationCredentials credentials,
                User user)
                throws UnsupportedAuthenticationCredentialsException {
            if (!(credentials instanceof GenericAuthenticationCredentials)) {
                user.getAuthenticationState()
                        .setLastAuthFailure("Credentials not GenericAuthenticationCredentials");
                throw new UnsupportedAuthenticationCredentialsException(
                        "Script based Authentication method only supports "
                                + GenericAuthenticationCredentials.class.getSimpleName()
                                + ". Received: "
                                + credentials.getClass());
            }
            GenericAuthenticationCredentials cred = (GenericAuthenticationCredentials) credentials;

            ScriptWrapper script = getScript();
            AuthenticationScript authScript = getAuthenticationScript(script);
            if (authScript == null) {
                return null;
            }
            LOGGER.debug("Script class: {}", authScript.getClass().getCanonicalName());
            ExtensionScript.recordScriptCalledStats(script);
            ZestAuthenticationRunner zestRunner = null;

            try (AuthenticationDiagnostics diags =
                    new AuthenticationDiagnostics(
                            diagnostics,
                            getName(),
                            user.getContext().getName(),
                            user.getName(),
                            script.getContents())) {
                try {
                    if (authScript instanceof AuthenticationScriptV2 scriptV2) {
                        setLoggedInIndicatorPattern(scriptV2.getLoggedInIndicator());
                        setLoggedOutIndicatorPattern(scriptV2.getLoggedOutIndicator());
                    }

                    if (authScript instanceof ZestAuthenticationRunner) {
                        zestRunner = (ZestAuthenticationRunner) authScript;
                        ZestScript zestScript = zestRunner.getScript().getZestScript();
                        if (!hasBrowserLaunch(zestScript)) {
                            LOGGER.warn("The script does not have any browser launch.");
                            return null;
                        }

                        zestRunner.setAutoCloseProxy(false);
                        zestRunner.registerHandler(getHandler(user));
                        zestScript.add(
                                new ZestActionSleep(TimeUnit.SECONDS.toMillis(getLoginPageWait())));
                        removeCloseStatements(zestScript);
                        if (minWaitFor > 0) {
                            AuthUtils.setMinWaitFor(
                                    zestScript, (int) TimeUnit.SECONDS.toMillis(minWaitFor));
                        }
                    } else {
                        LOGGER.warn("Expected authScript to be a Zest script");
                        return null;
                    }

                    HttpSender sender = getHttpSender();
                    sender.setUser(user);

                    diags.insertDiagnostics(zestRunner.getScript().getZestScript());
                    if (handler != null) {
                        handler.resetAuthMsg();
                    }

                    authScript.authenticate(
                            new AuthenticationHelper(sender, sessionManagementMethod, user),
                            getParamValues(),
                            cred);

                } catch (Exception e) {
                    diags.recordErrorStep(getWebDriver(zestRunner));

                    // Catch Exception instead of ScriptException and IOException because script
                    // engine
                    // implementations might throw other exceptions on script errors (e.g.
                    // jdk.nashorn.internal.runtime.ECMAException)
                    user.getAuthenticationState()
                            .setLastAuthFailure(
                                    "Error running authentication script " + e.getMessage());
                    LOGGER.error(
                            "An error occurred while trying to authenticate using the Authentication Script: {}",
                            script.getName(),
                            e);
                    getExtensionScript().handleScriptException(script, e);
                    return null;
                }

                // Wait until the authentication request is identified
                for (int i = 0; i < AuthUtils.getWaitLoopCount(); i++) {
                    if (handler.getAuthMsg() != null) {
                        break;
                    }
                    AuthUtils.sleep(AuthUtils.TIME_TO_SLEEP_IN_MSECS);
                }

                if (user.getContext().getAuthenticationMethod().getPollUrl() == null
                        && zestRunner != null
                        && !zestRunner.getWebDrivers().isEmpty()) {
                    // We failed to identify a suitable URL for polling.
                    // This can happen for more traditional apps - refresh the current one in case
                    // its a good option.
                    WebDriver wd = zestRunner.getWebDrivers().get(0);
                    wd.get(wd.getCurrentUrl());
                    AuthUtils.sleep(TimeUnit.SECONDS.toMillis(getLoginPageWait()));

                    diags.recordStep(
                            wd,
                            Constant.messages.getString(
                                    "authhelper.auth.method.diags.steps.refresh"));
                }

                HttpMessage authMsg = handler.getAuthMsg();
                if (authMsg != null) {
                    diags.recordStep(
                            authMsg,
                            Constant.messages.getString(
                                    "authhelper.auth.method.diags.steps.authmessage"));
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

                    AuthUtils.checkLoginLinkVerification(
                            getHttpSender(), user, authMsg.getRequestHeader().getURI().toString());

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

                    recordCloseStep(zestRunner, diags);
                    return session;
                }

                diags.recordStep(
                        Constant.messages.getString(
                                "authhelper.auth.method.diags.steps.emptysession"));
                WebSession session = sessionManagementMethod.createEmptyWebSession();

                recordCloseStep(zestRunner, diags);
                return session;

            } finally {
                if (zestRunner != null) {
                    zestRunner
                            .getWebDrivers()
                            .forEach(
                                    wd -> {
                                        try {
                                            wd.close();
                                        } catch (Exception e) {
                                            // Ignore
                                        }
                                    });
                    zestRunner.closeProxy();
                }
            }
        }

        private static WebDriver getWebDriver(ZestAuthenticationRunner runner) {
            if (runner != null && !runner.getWebDrivers().isEmpty()) {
                return runner.getWebDrivers().get(0);
            }
            return null;
        }

        private void recordCloseStep(
                ZestAuthenticationRunner zestRunner, AuthenticationDiagnostics diags) {
            if (zestRunner == null || !diagnostics) {
                return;
            }
            zestRunner
                    .getWebDrivers()
                    .forEach(
                            wd -> {
                                try {
                                    diags.recordStep(
                                            wd,
                                            Constant.messages.getString(
                                                    "authhelper.auth.method.diags.zest.close"));
                                } catch (Exception e) {
                                    // Ignore
                                }
                            });
        }
    }

    @SuppressWarnings("serial")
    public class ClientScriptBasedAuthenticationMethodOptionsPanel
            extends ScriptBasedAuthenticationMethodOptionsPanel {

        private static final long serialVersionUID = 1L;

        private ClientScriptBasedAuthenticationMethod shownMethod;

        private ZapNumberSpinner loginPageWait;
        private ZapNumberSpinner minWaitFor;
        private JCheckBox diagnostics;

        @Override
        protected int addCustomFields(int y) {
            int newY = y;

            loginPageWait = new ZapNumberSpinner(0, DEFAULT_PAGE_WAIT, Integer.MAX_VALUE);
            JLabel loginPageWaitLabel =
                    new JLabel(
                            Constant.messages.getString(
                                    "authhelper.auth.method.browser.label.loginWait"));
            loginPageWaitLabel.setLabelFor(loginPageWait);
            this.add(loginPageWaitLabel, LayoutHelper.getGBC(0, newY, 1, 1.0d, 0.0d));
            this.add(loginPageWait, LayoutHelper.getGBC(1, newY, 2, 1.0d, 0.0d));
            newY++;

            minWaitFor = new ZapNumberSpinner(0, DEFAULT_MIN_WAIT_FOR, Integer.MAX_VALUE);
            JLabel minWaitForLabel =
                    new JLabel(
                            Constant.messages.getString(
                                    "authhelper.auth.method.browser.label.minWaitFor"));
            minWaitForLabel.setLabelFor(minWaitFor);
            this.add(minWaitForLabel, LayoutHelper.getGBC(0, newY, 1, 1.0d, 0.0d));
            this.add(minWaitFor, LayoutHelper.getGBC(1, newY, 2, 1.0d, 0.0d));
            newY++;

            diagnostics = new JCheckBox();
            JLabel diagnosticsLabel =
                    new JLabel(
                            Constant.messages.getString(
                                    "authhelper.auth.method.browser.label.diagnostics"));
            diagnosticsLabel.setLabelFor(diagnostics);
            add(diagnosticsLabel, LayoutHelper.getGBC(0, newY, 1, 1.0d, 0.0d));
            add(diagnostics, LayoutHelper.getGBC(1, newY, 1, 1.0d, 0.0d));
            newY++;

            return newY;
        }

        @Override
        public void bindMethod(AuthenticationMethod method)
                throws UnsupportedAuthenticationMethodException {
            super.bindMethod(method);

            shownMethod = (ClientScriptBasedAuthenticationMethod) method;
            loginPageWait.setValue(shownMethod.getLoginPageWait());
            minWaitFor.setValue(shownMethod.getMinWaitFor());
            diagnostics.setSelected(shownMethod.isDiagnostics());
        }

        @Override
        public void saveMethod() {
            super.saveMethod();

            shownMethod.setLoginPageWait(loginPageWait.getValue());
            shownMethod.setMinWaitFor(minWaitFor.getValue());
            shownMethod.setDiagnostics(diagnostics.isSelected());
        }

        @Override
        protected List<ScriptWrapper> getAuthenticationScripts() {
            return super.getAuthenticationScripts().stream()
                    .filter(sc -> sc.getEngineName().contains("Zest"))
                    .toList();
        }
    }

    private ExtensionScript getExtensionScript() {
        if (extensionScript == null)
            extensionScript =
                    Control.getSingleton().getExtensionLoader().getExtension(ExtensionScript.class);
        return extensionScript;
    }

    @Override
    public void exportData(Configuration config, AuthenticationMethod authMethod) {
        super.exportData(config, authMethod);

        ClientScriptBasedAuthenticationMethod method =
                (ClientScriptBasedAuthenticationMethod) authMethod;
        config.setProperty(CONTEXT_CONFIG_LOGIN_PAGE_WAIT, method.getLoginPageWait());
        config.setProperty(CONTEXT_CONFIG_MIN_WAIT_FOR, method.getMinWaitFor());
    }

    @Override
    public void importData(Configuration config, AuthenticationMethod authMethod)
            throws ConfigurationException {
        super.importData(config, authMethod);

        ClientScriptBasedAuthenticationMethod method =
                (ClientScriptBasedAuthenticationMethod) authMethod;

        try {
            method.setLoginPageWait(config.getInt(CONTEXT_CONFIG_LOGIN_PAGE_WAIT));
        } catch (Exception e) {
            throw new ConfigurationException(e);
        }
        try {
            method.setMinWaitFor(config.getInt(CONTEXT_CONFIG_MIN_WAIT_FOR, DEFAULT_MIN_WAIT_FOR));
        } catch (Exception e) {
            throw new ConfigurationException(e);
        }
    }

    @Override
    public ApiDynamicActionImplementor getSetMethodForContextApiAction() {
        ApiDynamicActionImplementor impl = super.getSetMethodForContextApiAction();
        impl.setName(API_METHOD_NAME);
        return impl;
    }
}
