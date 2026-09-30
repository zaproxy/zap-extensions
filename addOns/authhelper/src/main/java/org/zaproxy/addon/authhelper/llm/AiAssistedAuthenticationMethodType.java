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
package org.zaproxy.addon.authhelper.llm;

import java.awt.Dimension;
import java.awt.GridBagLayout;
import java.io.File;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import net.sf.json.JSON;
import net.sf.json.JSONObject;
import org.apache.commons.configuration.Configuration;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openqa.selenium.WebDriver;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.db.RecordContext;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.authhelper.AiAssistedAuthTesterSupport;
import org.zaproxy.addon.authhelper.AuthMethodOptionsPanelUtils;
import org.zaproxy.addon.authhelper.AuthUtils;
import org.zaproxy.addon.authhelper.ClientScriptBasedAuthenticationMethodType;
import org.zaproxy.addon.authhelper.ClientScriptBasedAuthenticationMethodType.ClientScriptBasedAuthenticationMethod;
import org.zaproxy.addon.llm.ExtensionLlm;
import org.zaproxy.addon.llm.services.LlmCommunicationService;
import org.zaproxy.addon.llm.ui.LlmChatTabPanel;
import org.zaproxy.zap.authentication.AbstractAuthenticationMethodOptionsPanel;
import org.zaproxy.zap.authentication.AbstractCredentialsOptionsPanel;
import org.zaproxy.zap.authentication.AuthenticationCredentials;
import org.zaproxy.zap.authentication.AuthenticationMethod;
import org.zaproxy.zap.authentication.AuthenticationMethodType;
import org.zaproxy.zap.authentication.GenericAuthenticationCredentials;
import org.zaproxy.zap.authentication.UsernamePasswordAuthenticationCredentials;
import org.zaproxy.zap.authentication.UsernamePasswordAuthenticationCredentials.UsernamePasswordAuthenticationCredentialsOptionsPanel;
import org.zaproxy.zap.extension.api.ApiDynamicActionImplementor;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.extension.api.ApiResponse;
import org.zaproxy.zap.extension.api.ApiResponseSet;
import org.zaproxy.zap.extension.authentication.AuthenticationAPI;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.selenium.Browser;
import org.zaproxy.zap.extension.selenium.BrowserUI;
import org.zaproxy.zap.extension.selenium.BrowsersComboBoxModel;
import org.zaproxy.zap.extension.selenium.ExtensionSelenium;
import org.zaproxy.zap.extension.zest.ExtensionZest;
import org.zaproxy.zap.extension.zest.ZestScriptWrapper;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.session.SessionManagementMethod;
import org.zaproxy.zap.session.WebSession;
import org.zaproxy.zap.users.User;
import org.zaproxy.zap.utils.ApiUtils;
import org.zaproxy.zap.utils.ThreadUtils;
import org.zaproxy.zap.utils.ZapNumberSpinner;
import org.zaproxy.zap.utils.ZapTextField;
import org.zaproxy.zap.view.LayoutHelper;

public class AiAssistedAuthenticationMethodType extends AuthenticationMethodType {

    public static final int METHOD_IDENTIFIER = 9;

    private static final String API_METHOD_NAME = "aiAssistedAuthentication";

    private static final String CONTEXT_CONFIG_AUTH_AI =
            AuthenticationMethod.CONTEXT_CONFIG_AUTH + ".ai";
    private static final String CONTEXT_CONFIG_AUTH_AI_LOGINPAGEURL =
            CONTEXT_CONFIG_AUTH_AI + ".loginpageurl";
    private static final String CONTEXT_CONFIG_AUTH_AI_LOGINPAGEWAIT =
            CONTEXT_CONFIG_AUTH_AI + ".loginpagewait";
    private static final String CONTEXT_CONFIG_AUTH_AI_BROWSERID =
            CONTEXT_CONFIG_AUTH_AI + ".browserid";
    private static final String CONTEXT_CONFIG_AUTH_AI_HINT = CONTEXT_CONFIG_AUTH_AI + ".hint";

    private static final String PARAM_LOGIN_PAGE_URL = "loginPageUrl";
    private static final String PARAM_BROWSER_ID = "browserId";
    private static final String PARAM_LOGIN_PAGE_WAIT = "loginPageWait";
    private static final String PARAM_HINT = "hint";

    public static final String DEFAULT_BROWSER_ID = Browser.FIREFOX_HEADLESS.getId();
    private static final int DEFAULT_PAGE_WAIT = 5;

    private static final Logger LOGGER =
            LogManager.getLogger(AiAssistedAuthenticationMethodType.class);

    public class AiAssistedAuthenticationMethod extends AuthenticationMethod
            implements AiAssistedAuthTesterSupport {

        private String loginPageUrl;
        private String browserId = DEFAULT_BROWSER_ID;
        private int loginPageWait = DEFAULT_PAGE_WAIT;
        private String hint = "";

        public AiAssistedAuthenticationMethod() {}

        public AiAssistedAuthenticationMethod(AiAssistedAuthenticationMethod method) {
            this.loginPageUrl = method.loginPageUrl;
            this.browserId = method.browserId;
            this.loginPageWait = method.loginPageWait;
            this.hint = method.hint;
        }

        @Override
        public boolean isConfigured() {
            return !StringUtils.isBlank(loginPageUrl);
        }

        @Override
        protected AuthenticationMethod duplicate() {
            return new AiAssistedAuthenticationMethod(this);
        }

        @Override
        public AuthenticationCredentials createAuthenticationCredentials() {
            return new UsernamePasswordAuthenticationCredentials();
        }

        @Override
        public AuthenticationMethodType getType() {
            return new AiAssistedAuthenticationMethodType();
        }

        public String getLoginPageUrl() {
            return loginPageUrl;
        }

        @Override
        public void setLoginPageUrl(String loginPageUrl) {
            this.loginPageUrl = loginPageUrl;
        }

        public String getBrowserId() {
            return browserId;
        }

        @Override
        public void setBrowserId(String browserId) {
            if (!StringUtils.isEmpty(browserId)) {
                this.browserId = browserId;
            }
        }

        public int getLoginPageWait() {
            return loginPageWait;
        }

        @Override
        public void setLoginPageWait(int loginPageWait) {
            this.loginPageWait = loginPageWait;
        }

        public String getHint() {
            return hint;
        }

        @Override
        public void setHint(String hint) {
            this.hint = hint != null ? hint : "";
        }

        @Override
        public String checkPrerequisites() {
            if (!AuthUtils.getExtension(ExtensionLlm.class).isConfigured()) {
                return Constant.messages.getString(
                        "authhelper.auth.method.ai.error.llm.notconfigured");
            }
            return null;
        }

        @Override
        public WebSession authenticate(
                SessionManagementMethod sessionManagementMethod,
                AuthenticationCredentials credentials,
                User user)
                throws UnsupportedAuthenticationCredentialsException {
            if (!(credentials instanceof UsernamePasswordAuthenticationCredentials)) {
                LOGGER.error(
                        "Unsupported credentials type: {}",
                        credentials == null ? "null" : credentials.getClass());
                return sessionManagementMethod.createEmptyWebSession();
            }
            UsernamePasswordAuthenticationCredentials upCreds =
                    (UsernamePasswordAuthenticationCredentials) credentials;

            String prerequisitesIssue = checkPrerequisites();
            if (prerequisitesIssue != null) {
                LOGGER.error(prerequisitesIssue);
                user.getAuthenticationState().setLastAuthFailure(prerequisitesIssue);
                return sessionManagementMethod.createEmptyWebSession();
            }

            ExtensionLlm extLlm = AuthUtils.getExtension(ExtensionLlm.class);
            LlmCommunicationService llm =
                    extLlm.getCommunicationService("authhelper-ai-auth", null);
            if (llm == null) {
                LOGGER.error("Could not obtain LLM communication service");
                return sessionManagementMethod.createEmptyWebSession();
            }

            ExtensionSelenium extSel = AuthUtils.getExtension(ExtensionSelenium.class);

            LlmChatTabPanel chatTab =
                    extLlm.getOrCreateChatTab(
                            "authhelper-ai-auth",
                            Constant.messages.getString(
                                    "authhelper.auth.method.ai.chat.tab.title"));

            WebDriver wd = null;
            try {
                wd = extSel.getProxiedBrowser(browserId);
                AiAuthScriptGenerator generator = new AiAuthScriptGenerator(this, llm, chatTab);
                AiAuthResult result =
                        generator.run(wd, upCreds.getUsername(), upCreds.getPassword());
                if (result.success()) {
                    LOGGER.info("AI authentication succeeded: {}", result.reasoning());
                    if (switchToClientScriptAuth(
                            user, generator.getSuccessfulActions(), upCreds, chatTab)) {
                        AuthUtils.incStatsCounter(loginPageUrl, AuthUtils.AUTH_AI_SUCCEEDED_STATS);
                    } else {
                        LOGGER.warn(
                                "AI authentication succeeded but failed to switch the context to"
                                        + " Client Script Authentication");
                        AuthUtils.incStatsCounter(loginPageUrl, AuthUtils.AUTH_AI_FAILED_STATS);
                    }
                } else {
                    LOGGER.warn(
                            "AI authentication did not succeed: state={}, reason={}",
                            result.finalState(),
                            result.reasoning());
                    AuthUtils.incStatsCounter(loginPageUrl, AuthUtils.AUTH_AI_FAILED_STATS);
                }
            } catch (Exception e) {
                LOGGER.error("AI authentication threw an exception", e);
            } finally {
                if (wd != null) {
                    try {
                        wd.quit();
                    } catch (Exception e) {
                        LOGGER.debug("Error closing WebDriver", e);
                    }
                }
            }
            return sessionManagementMethod.createEmptyWebSession();
        }

        private boolean switchToClientScriptAuth(
                User user,
                List<AiAuthActionResult> actions,
                UsernamePasswordAuthenticationCredentials upCreds,
                LlmChatTabPanel chatTab) {
            try {
                ExtensionZest extZest = AuthUtils.getExtension(ExtensionZest.class);
                ExtensionScript extScript = AuthUtils.getExtension(ExtensionScript.class);
                if (extZest == null || extScript == null) {
                    LOGGER.warn(
                            "Zest or Script extension not available — skipping script generation");
                    return false;
                }

                String scriptName = deriveScriptName();

                // Re-running AI auth against the same login page derives the same script name;
                // replace any script left over from a previous run rather than failing to add it.
                ScriptWrapper existingScript = extScript.getScript(scriptName);
                if (existingScript != null) {
                    extScript.removeScript(existingScript);
                }

                ZestScriptWrapper zsw =
                        AiAuthZestBuilder.build(
                                scriptName, loginPageUrl, browserId, actions, extZest, extScript);

                File f =
                        Paths.get(
                                        Constant.getZapHome(),
                                        ExtensionScript.SCRIPTS_DIR,
                                        ExtensionScript.SCRIPTS_DIR,
                                        zsw.getTypeName(),
                                        zsw.getName() + ".zst")
                                .toFile();
                zsw.setFile(f);
                extScript.saveScript(zsw);

                ThreadUtils.invokeAndWait(() -> extZest.add(zsw, false));
                LOGGER.info("Registered Zest authentication script: {}", scriptName);

                ClientScriptBasedAuthenticationMethod clientMethod =
                        new ClientScriptBasedAuthenticationMethodType()
                                .createAuthenticationMethod(user.getContextId());
                clientMethod.setScriptWrapper(zsw);
                clientMethod.setParamValues(new HashMap<>());

                // Copy any verification settings already detected on the current method.
                // The passive scanner may have set these during the browser session; if we
                // replace the auth method without copying them they would be lost.
                AuthenticationMethod existingMethod = user.getContext().getAuthenticationMethod();
                clientMethod.setAuthCheckingStrategy(existingMethod.getAuthCheckingStrategy());
                clientMethod.setPollUrl(existingMethod.getPollUrl());
                clientMethod.setPollData(existingMethod.getPollData());
                clientMethod.setPollHeaders(existingMethod.getPollHeaders());
                clientMethod.setPollFrequency(existingMethod.getPollFrequency());
                clientMethod.setPollFrequencyUnits(existingMethod.getPollFrequencyUnits());
                if (existingMethod.getLoggedInIndicatorPattern() != null) {
                    clientMethod.setLoggedInIndicatorPattern(
                            existingMethod.getLoggedInIndicatorPattern().pattern());
                }
                if (existingMethod.getLoggedOutIndicatorPattern() != null) {
                    clientMethod.setLoggedOutIndicatorPattern(
                            existingMethod.getLoggedOutIndicatorPattern().pattern());
                }

                GenericAuthenticationCredentials genericCreds =
                        new GenericAuthenticationCredentials(new String[] {"username", "password"});
                genericCreds.setParam("username", upCreds.getUsername());
                genericCreds.setParam("password", upCreds.getPassword());
                user.setAuthenticationCredentials(genericCreds);

                user.getContext().setAuthenticationMethod(clientMethod);
                LOGGER.info(
                        "Switched context to Client Script Authentication using script: {}",
                        scriptName);

                if (chatTab != null) {
                    chatTab.appendToOutput(
                            LlmChatTabPanel.ASSISTANT_LABEL,
                            Constant.messages.getString(
                                    "authhelper.auth.method.ai.chat.script.created", scriptName));
                }
                return true;
            } catch (Exception e) {
                LOGGER.warn("Failed to generate Zest authentication script", e);
                return false;
            }
        }

        private String deriveScriptName() {
            try {
                java.net.URI uri = new java.net.URI(loginPageUrl);
                String host = uri.getHost();
                int port = uri.getPort();
                String hostPart = (port > 0) ? host + ":" + port : host;
                return "AI Auth - " + hostPart;
            } catch (Exception e) {
                return "AI Auth Script";
            }
        }

        @Override
        public ApiResponse getApiResponseRepresentation() {
            Map<String, Object> values = new HashMap<>();
            values.put(PARAM_LOGIN_PAGE_URL, loginPageUrl);
            values.put(PARAM_BROWSER_ID, browserId);
            values.put(PARAM_LOGIN_PAGE_WAIT, loginPageWait);
            values.put(PARAM_HINT, hint);
            return new AuthMethodApiResponseRepresentation<>(values);
        }

        @Override
        public void replaceUserDataInPollRequest(HttpMessage msg, User user) {
            user.processMessageToMatchAuthenticatedSession(msg);
        }
    }

    @Override
    public AiAssistedAuthenticationMethod createAuthenticationMethod(int contextId) {
        return new AiAssistedAuthenticationMethod();
    }

    @Override
    public String getName() {
        return Constant.messages.getString("authhelper.auth.method.ai.name");
    }

    @Override
    public int getUniqueIdentifier() {
        return METHOD_IDENTIFIER;
    }

    @Override
    public AbstractAuthenticationMethodOptionsPanel buildOptionsPanel(Context uiSharedContext) {
        return new AiAssistedAuthenticationMethodOptionsPanel(uiSharedContext);
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
        return method instanceof AiAssistedAuthenticationMethod;
    }

    @Override
    public void hook(ExtensionHook extensionHook) {}

    @Override
    public AuthenticationMethod loadMethodFromSession(Session session, int contextId)
            throws DatabaseException {
        AiAssistedAuthenticationMethod method = createAuthenticationMethod(contextId);
        method.setLoginPageUrl(
                session.getContextDataString(
                        contextId, RecordContext.TYPE_AUTH_METHOD_FIELD_1, ""));
        method.setBrowserId(
                session.getContextDataString(
                        contextId, RecordContext.TYPE_AUTH_METHOD_FIELD_2, DEFAULT_BROWSER_ID));
        String loginWaitStr =
                session.getContextDataString(contextId, RecordContext.TYPE_AUTH_METHOD_FIELD_3, "");
        if (!StringUtils.isEmpty(loginWaitStr)) {
            try {
                method.setLoginPageWait(Integer.parseInt(loginWaitStr));
            } catch (NumberFormatException e) {
                // Ignore
            }
        }
        method.setHint(
                session.getContextDataString(
                        contextId, RecordContext.TYPE_AUTH_METHOD_FIELD_4, ""));
        return method;
    }

    @Override
    public void persistMethodToSession(
            Session session, int contextId, AuthenticationMethod authMethod)
            throws DatabaseException {
        if (!(authMethod instanceof AiAssistedAuthenticationMethod)) {
            throw new UnsupportedAuthenticationMethodException(
                    "AI assisted authentication type only supports: "
                            + AiAssistedAuthenticationMethod.class);
        }
        AiAssistedAuthenticationMethod method = (AiAssistedAuthenticationMethod) authMethod;
        session.setContextData(
                contextId, RecordContext.TYPE_AUTH_METHOD_FIELD_1, method.loginPageUrl);
        session.setContextData(contextId, RecordContext.TYPE_AUTH_METHOD_FIELD_2, method.browserId);
        session.setContextData(
                contextId,
                RecordContext.TYPE_AUTH_METHOD_FIELD_3,
                Integer.toString(method.loginPageWait));
        session.setContextData(contextId, RecordContext.TYPE_AUTH_METHOD_FIELD_4, method.hint);
    }

    @Override
    public void exportData(Configuration config, AuthenticationMethod authMethod) {
        if (!(authMethod instanceof AiAssistedAuthenticationMethod)) {
            throw new UnsupportedAuthenticationMethodException(
                    "AI assisted authentication type only supports: "
                            + AiAssistedAuthenticationMethod.class);
        }
        AiAssistedAuthenticationMethod method = (AiAssistedAuthenticationMethod) authMethod;
        config.setProperty(CONTEXT_CONFIG_AUTH_AI_LOGINPAGEURL, method.loginPageUrl);
        config.setProperty(CONTEXT_CONFIG_AUTH_AI_BROWSERID, method.browserId);
        config.setProperty(CONTEXT_CONFIG_AUTH_AI_LOGINPAGEWAIT, method.loginPageWait);
        config.setProperty(CONTEXT_CONFIG_AUTH_AI_HINT, method.hint);
    }

    @Override
    public void importData(Configuration config, AuthenticationMethod authMethod)
            throws ConfigurationException {
        if (!(authMethod instanceof AiAssistedAuthenticationMethod)) {
            throw new UnsupportedAuthenticationMethodException(
                    "AI assisted authentication type only supports: "
                            + AiAssistedAuthenticationMethod.class);
        }
        AiAssistedAuthenticationMethod method = (AiAssistedAuthenticationMethod) authMethod;
        try {
            method.setLoginPageUrl(config.getString(CONTEXT_CONFIG_AUTH_AI_LOGINPAGEURL));
        } catch (Exception e) {
            throw new ConfigurationException(e);
        }
        try {
            method.setBrowserId(config.getString(CONTEXT_CONFIG_AUTH_AI_BROWSERID));
        } catch (Exception e) {
            throw new ConfigurationException(e);
        }
        try {
            method.setLoginPageWait(config.getInt(CONTEXT_CONFIG_AUTH_AI_LOGINPAGEWAIT));
        } catch (Exception e) {
            throw new ConfigurationException(e);
        }
        try {
            method.setHint(config.getString(CONTEXT_CONFIG_AUTH_AI_HINT, ""));
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
        String[] optionalParamNames =
                new String[] {PARAM_BROWSER_ID, PARAM_LOGIN_PAGE_WAIT, PARAM_HINT};
        return new ApiDynamicActionImplementor(
                API_METHOD_NAME, mandatoryParamNames, optionalParamNames) {

            @Override
            public void handleAction(JSONObject params) throws ApiException {
                Context context =
                        ApiUtils.getContextByParamId(params, AuthenticationAPI.PARAM_CONTEXT_ID);

                AiAssistedAuthenticationMethod method = createAuthenticationMethod(context.getId());
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

                    String hint = ApiUtils.getOptionalStringParam(params, PARAM_HINT);
                    if (hint != null) {
                        method.setHint(hint);
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

    @SuppressWarnings("serial")
    protected class AiAssistedAuthenticationMethodOptionsPanel
            extends AbstractAuthenticationMethodOptionsPanel {

        private static final long serialVersionUID = 1L;

        private AiAssistedAuthenticationMethod authenticationMethod;

        private ZapTextField loginUrlField;
        private JComboBox<BrowserUI> browserCombo;
        private ZapNumberSpinner loginUrlWait;
        private JTextArea hintArea;

        public AiAssistedAuthenticationMethodOptionsPanel(Context context) {
            this.setLayout(new GridBagLayout());

            ExtensionSelenium extSel = AuthUtils.getExtension(ExtensionSelenium.class);
            AuthMethodOptionsPanelUtils.LoginUrlBrowserWaitFields fields =
                    AuthMethodOptionsPanelUtils.addLoginUrlBrowserWaitFields(
                            this, extSel, DEFAULT_PAGE_WAIT);
            loginUrlField = fields.loginUrlField();
            browserCombo = fields.browserCombo();
            loginUrlWait = fields.loginUrlWait();

            hintArea = new JTextArea(8, 30);
            hintArea.setLineWrap(true);
            hintArea.setWrapStyleWord(true);
            JScrollPane hintScroll = new JScrollPane(hintArea);
            // Guarantee at least 2 text lines are visible, since the containing panel has a
            // fixed size and can otherwise squash this field down when space is tight.
            int minHeight =
                    hintArea.getFontMetrics(hintArea.getFont()).getHeight() * 2
                            + hintScroll.getInsets().top
                            + hintScroll.getInsets().bottom;
            hintScroll.setMinimumSize(new Dimension(hintScroll.getMinimumSize().width, minHeight));
            JLabel hintLabel =
                    new JLabel(Constant.messages.getString("authhelper.auth.method.ai.label.hint"));
            hintLabel.setLabelFor(hintArea);
            add(hintLabel, LayoutHelper.getGBC(0, 4, 2, 1.0d, 0.0d));
            add(hintScroll, LayoutHelper.getGBC(0, 5, 2, 1.0d, 1.0d));
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
            getMethod().setHint(hintArea.getText());
        }

        @Override
        public void bindMethod(AuthenticationMethod method)
                throws UnsupportedAuthenticationMethodException {
            authenticationMethod = (AiAssistedAuthenticationMethod) method;
            loginUrlField.setText(authenticationMethod.getLoginPageUrl());
            ((BrowsersComboBoxModel) browserCombo.getModel())
                    .setSelectedBrowser(authenticationMethod.getBrowserId());
            loginUrlWait.setValue(authenticationMethod.getLoginPageWait());
            hintArea.setText(authenticationMethod.getHint());
        }

        @Override
        public AiAssistedAuthenticationMethod getMethod() {
            return authenticationMethod;
        }
    }

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
