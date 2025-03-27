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

import java.awt.BorderLayout;
import java.awt.Font;
import java.awt.GridBagLayout;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.stream.Collectors;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import org.apache.commons.configuration.Configuration;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jdesktop.swingx.JXComboBox;
import org.jdesktop.swingx.decorator.FontHighlighter;
import org.jdesktop.swingx.renderer.DefaultListRenderer;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.authhelper.internal.ClientSideHandler;
import org.zaproxy.addon.commonlib.internal.TotpSupport;
import org.zaproxy.addon.network.server.HttpMessageHandler;
import org.zaproxy.zap.authentication.AbstractAuthenticationMethodOptionsPanel;
import org.zaproxy.zap.authentication.AuthenticationCredentials;
import org.zaproxy.zap.authentication.AuthenticationHelper;
import org.zaproxy.zap.authentication.AuthenticationIndicatorsPanel;
import org.zaproxy.zap.authentication.AuthenticationMethod;
import org.zaproxy.zap.authentication.AuthenticationMethodType;
import org.zaproxy.zap.authentication.GenericAuthenticationCredentials;
import org.zaproxy.zap.authentication.ScriptBasedAuthenticationMethodType;
import org.zaproxy.zap.extension.api.ApiDynamicActionImplementor;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.zest.ZestAuthenticationRunner;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.session.SessionManagementMethod;
import org.zaproxy.zap.session.WebSession;
import org.zaproxy.zap.users.User;
import org.zaproxy.zap.utils.EncodingUtils;
import org.zaproxy.zap.utils.ZapHtmlLabel;
import org.zaproxy.zap.view.DynamicFieldsPanel;
import org.zaproxy.zap.view.LayoutHelper;
import org.zaproxy.zest.core.v1.ZestActionSleep;
import org.zaproxy.zest.core.v1.ZestClientWindowClose;
import org.zaproxy.zest.core.v1.ZestScript;
import org.zaproxy.zest.core.v1.ZestStatement;

public class ClientScriptBasedAuthenticationMethodType extends ScriptBasedAuthenticationMethodType {

    public static final int METHOD_IDENTIFIER = 8;
    private static final String API_METHOD_NAME = "clientScriptBasedAuthentication";

    private static final Logger LOGGER =
            LogManager.getLogger(ClientScriptBasedAuthenticationMethodType.class);

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
    public AbstractAuthenticationMethodOptionsPanel buildOptionsPanel(Context uiSharedContext) {
        return new ClientScriptBasedAuthenticationMethodOptionsPanel();
    }

    public class ClientScriptBasedAuthenticationMethod extends ScriptBasedAuthenticationMethod {

        private boolean diagnostics;
        private ScriptWrapper script;

        private String[] credentialsParamNames;

        private Map<String, String> paramValues;

        public void setDiagnostics(boolean diagnostics) {
            this.diagnostics = diagnostics;
        }

        public boolean isDiagnostics() {
            return diagnostics;
        }

        /**
         * Load a script and fills in the method's parameters according to the values specified by
         * the script.
         *
         * <p>If the method already had a loaded script and a set of values for the parameters, it
         * tries to provide new values for the new parameters if they match any previous parameter
         * names.
         *
         * @param scriptW the script wrapper
         * @throws IllegalArgumentException if an error occurs while loading the script.
         */
        @Override
        public void loadScript(ScriptWrapper scriptW) {
            AuthenticationScript authScript = getAuthScriptInterfaceV2(scriptW);
            if (authScript == null) {
                authScript = getAuthScriptInterface(scriptW);
            }
            if (authScript == null) {
                LOGGER.warn(
                        "The script {} does not properly implement the Authentication Script interface.",
                        scriptW.getName());
                throw new IllegalArgumentException(
                        Constant.messages.getString(
                                "authentication.method.script.dialog.error.text.interface",
                                scriptW.getName()));
            }

            try {
                if (authScript instanceof AuthenticationScriptV2 scriptV2) {
                    setLoggedInIndicatorPattern(scriptV2.getLoggedInIndicator());
                    setLoggedOutIndicatorPattern(scriptV2.getLoggedOutIndicator());
                }
                String[] requiredParams = authScript.getRequiredParamsNames();
                String[] optionalParams = authScript.getOptionalParamsNames();
                this.credentialsParamNames = authScript.getCredentialsParamsNames();
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug(
                            "Loaded authentication script - required parameters: {} - optional parameters: {}",
                            Arrays.toString(requiredParams),
                            Arrays.toString(optionalParams));
                }
                // If there's an already loaded script, make sure we save its values and _try_
                // to use them
                Map<String, String> oldValues =
                        this.paramValues != null
                                ? this.paramValues
                                : Collections.<String, String>emptyMap();
                this.paramValues = new HashMap<>(requiredParams.length + optionalParams.length);
                for (String param : requiredParams)
                    this.paramValues.put(param, oldValues.get(param));
                for (String param : optionalParams)
                    this.paramValues.put(param, oldValues.get(param));

                this.script = scriptW;
                LOGGER.info(
                        "Successfully loaded new script for ClientScriptBasedAuthentication: {}",
                        this);
            } catch (Exception e) {
                LOGGER.error("Error while loading authentication script", e);
                getExtensionScript().handleScriptException(this.script, e);
                throw new IllegalArgumentException(
                        Constant.messages.getString(
                                "authentication.method.script.dialog.error.text.loading",
                                e.getMessage()));
            }
        }

        @Override
        public String toString() {
            return "ClientScriptBasedAuthenticationMethod [script="
                    + script
                    + ", paramValues="
                    + paramValues
                    + ", credentialsParamNames="
                    + Arrays.toString(credentialsParamNames)
                    + "]";
        }

        @Override
        public boolean isConfigured() {
            return true;
        }

        @Override
        public AuthenticationMethod duplicate() {
            ClientScriptBasedAuthenticationMethod method =
                    new ClientScriptBasedAuthenticationMethod();
            method.diagnostics = diagnostics;
            method.script = script;
            method.paramValues = this.paramValues != null ? new HashMap<>(this.paramValues) : null;
            method.credentialsParamNames = this.credentialsParamNames;
            return method;
        }

        @Override
        public boolean validateCreationOfAuthenticationCredentials() {
            if (credentialsParamNames != null) {
                return true;
            }

            if (View.isInitialised()) {
                View.getSingleton()
                        .showMessageDialog(
                                Constant.messages.getString(
                                        "authentication.method.script.dialog.error.text.notLoaded"));
            }

            return false;
        }

        @Override
        public AuthenticationCredentials createAuthenticationCredentials() {
            return TotpSupport.createGenericAuthenticationCredentials(credentialsParamNames);
        }

        @Override
        public AuthenticationMethodType getType() {
            return new ClientScriptBasedAuthenticationMethodType();
        }

        public ScriptWrapper getScriptWrapper() {
            return this.script;
        }

        public ZestScript getZestScript() {
            AuthenticationScript authScript = getAuthScriptInterfaceV2(this.script);
            if (authScript == null) {
                authScript = getAuthScriptInterface(this.script);
            }

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

        private Set<String> getClientClosedWindowHandles(ZestScript zestScript) {
            return zestScript.getStatements().stream()
                    .filter(ZestClientWindowClose.class::isInstance)
                    .map(ZestClientWindowClose.class::cast)
                    .map(ZestClientWindowClose::getWindowHandle)
                    .collect(Collectors.toSet());
        }

        protected void appendCloseStatements(ZestScript zestScript) {
            ZestStatement last = zestScript.getLast();
            if (!(last instanceof ZestClientWindowClose)) {
                // Potentially need to add at least one close statement
                Set<String> handles = zestScript.getClientWindowHandles();
                handles.removeAll(this.getClientClosedWindowHandles(zestScript));
                if (!handles.isEmpty()) {
                    zestScript.add(new ZestActionSleep(2000));
                    handles.forEach(h -> zestScript.add(new ZestClientWindowClose(h, 1)));
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

            // Call the script to get an authenticated message from which we can then extract the
            // session
            AuthenticationScript authScript = getAuthScriptInterfaceV2(this.script);
            if (authScript == null) {
                authScript = getAuthScriptInterface(this.script);
            }

            if (authScript == null) {
                return null;
            }
            LOGGER.debug("Script class: {}", authScript.getClass().getCanonicalName());
            ExtensionScript.recordScriptCalledStats(this.script);

            try {
                if (authScript instanceof AuthenticationScriptV2 scriptV2) {
                    setLoggedInIndicatorPattern(scriptV2.getLoggedInIndicator());
                    setLoggedOutIndicatorPattern(scriptV2.getLoggedOutIndicator());
                }

                if (authScript instanceof ZestAuthenticationRunner zestRunner) {
                    zestRunner.registerHandler(getHandler(user));
                    appendCloseStatements(zestRunner.getScript().getZestScript());
                } else {
                    LOGGER.warn("Expected authScript to be a Zest script");
                    return null;
                }

                HttpSender sender = getHttpSender();
                sender.setUser(user);

                try (AuthenticationDiagnostics diags =
                        new AuthenticationDiagnostics(
                                diagnostics,
                                getName(),
                                user.getContext().getName(),
                                user.getName())) {
                    diags.insertDiagnostics(zestRunner.getScript().getZestScript());

                    authScript.authenticate(
                            new AuthenticationHelper(sender, sessionManagementMethod, user),
                            this.paramValues,
                            cred);
                }
            } catch (Exception e) {
                // Catch Exception instead of ScriptException and IOException because script engine
                // implementations might throw other exceptions on script errors (e.g.
                // jdk.nashorn.internal.runtime.ECMAException)
                user.getAuthenticationState()
                        .setLastAuthFailure(
                                "Error running authentication script " + e.getMessage());
                LOGGER.error(
                        "An error occurred while trying to authenticate using the Authentication Script: {}",
                        this.script.getName(),
                        e);
                getExtensionScript().handleScriptException(this.script, e);
                return null;
            }

            // Wait until the authentication request is identified
            for (int i = 0; i < AuthUtils.getWaitLoopCount(); i++) {
                if (handler.getAuthMsg() != null) {
                    break;
                }
                AuthUtils.sleep(AuthUtils.TIME_TO_SLEEP_IN_MSECS);
            }

            HttpMessage authMsg = handler.getAuthMsg();
            if (authMsg != null) {
                // Update the session as it may have changed
                WebSession session = sessionManagementMethod.extractWebSession(authMsg);
                user.setAuthenticatedSession(session);

                AuthUtils.checkLoginLinkVerification(
                        getHttpSender(),
                        user,
                        session,
                        authMsg.getRequestHeader().getURI().toString());

                if (this.isAuthenticated(authMsg, user, true)) {
                    // Let the user know it worked
                    AuthenticationHelper.notifyOutputAuthSuccessful(authMsg);
                    user.getAuthenticationState().setLastAuthFailure("");
                } else {
                    // Let the user know it failed
                    AuthenticationHelper.notifyOutputAuthFailure(authMsg);
                }
                return session;
            }

            // We don't expect this to work, but it will prevent some NPEs
            return sessionManagementMethod.extractWebSession(handler.getFallbackMsg());
        }

        @Override
        public void replaceUserDataInPollRequest(HttpMessage msg, User user) {
            AuthenticationHelper.replaceUserDataInRequest(
                    msg, wrapKeys(this.paramValues), NULL_ENCODER);
        }
    }

    private static Map<String, String> wrapKeys(Map<String, String> kvPairs) {
        Map<String, String> map = new HashMap<>();
        for (Entry<String, String> kv : kvPairs.entrySet()) {
            map.put(
                    AuthenticationMethod.TOKEN_PREFIX
                            + kv.getKey()
                            + AuthenticationMethod.TOKEN_POSTFIX,
                    kv.getValue() == null ? "" : kv.getValue());
        }
        return map;
    }

    @SuppressWarnings("serial")
    public class ClientScriptBasedAuthenticationMethodOptionsPanel
            extends AbstractAuthenticationMethodOptionsPanel {

        private static final long serialVersionUID = 7812841049435409987L;

        private static final String SCRIPT_NAME_LABEL =
                Constant.messages.getString("authentication.method.script.field.label.scriptName");
        private static final String LABEL_NOT_LOADED =
                Constant.messages.getString("authentication.method.script.field.label.notLoaded");
        private JXComboBox scriptsComboBox;
        private JButton loadScriptButton;

        private ClientScriptBasedAuthenticationMethod method;
        private AuthenticationIndicatorsPanel indicatorsPanel;

        private ScriptWrapper loadedScript;

        private JPanel dynamicContentPanel;

        private DynamicFieldsPanel dynamicFieldsPanel;

        private String[] loadedCredentialParams;

        public ClientScriptBasedAuthenticationMethodOptionsPanel() {
            super();
            initialize();
        }

        private void initialize() {
            this.setLayout(new GridBagLayout());

            this.add(new JLabel(SCRIPT_NAME_LABEL), LayoutHelper.getGBC(0, 0, 1, 0.0d, 0.0d));

            scriptsComboBox = new JXComboBox();
            scriptsComboBox.addHighlighter(
                    new FontHighlighter(
                            (renderer, adapter) -> loadedScript == adapter.getValue(),
                            scriptsComboBox.getFont().deriveFont(Font.BOLD)));
            scriptsComboBox.setRenderer(
                    new DefaultListRenderer(
                            sw -> {
                                if (sw == null) {
                                    return null;
                                }

                                String name = ((ScriptWrapper) sw).getName();
                                if (loadedScript == sw) {
                                    return Constant.messages.getString(
                                            "authentication.method.script.loaded", name);
                                }
                                return name;
                            }));
            this.add(this.scriptsComboBox, LayoutHelper.getGBC(1, 0, 1, 1.0d, 0.0d));

            this.loadScriptButton =
                    new JButton(
                            Constant.messages.getString(
                                    "authentication.method.script.load.button"));
            this.add(this.loadScriptButton, LayoutHelper.getGBC(2, 0, 1, 0.0d, 0.0d));
            this.loadScriptButton.addActionListener(
                    e -> loadScript((ScriptWrapper) scriptsComboBox.getSelectedItem(), true));

            // Make sure the 'Load' button is disabled when nothing is selected
            this.loadScriptButton.setEnabled(false);
            this.scriptsComboBox.addActionListener(
                    e -> loadScriptButton.setEnabled(scriptsComboBox.getSelectedIndex() >= 0));

            this.dynamicContentPanel = new JPanel(new BorderLayout());
            this.add(this.dynamicContentPanel, LayoutHelper.getGBC(0, 1, 3, 1.0d, 0.0d));
            this.dynamicContentPanel.add(new ZapHtmlLabel(LABEL_NOT_LOADED));
        }

        @Override
        public void validateFields() throws IllegalStateException {
            if (this.loadedScript == null) {
                this.scriptsComboBox.requestFocusInWindow();
                throw new IllegalStateException(
                        Constant.messages.getString(
                                "authentication.method.script.dialog.error.text.notLoadedNorConfigured"));
            }
            this.dynamicFieldsPanel.validateFields();
        }

        @Override
        public void saveMethod() {
            this.method.script = (ScriptWrapper) this.scriptsComboBox.getSelectedItem();
            // This method will also be called when switching panels to save a temporary state so
            // the state of the authentication method might not be valid
            if (this.dynamicFieldsPanel != null)
                this.method.paramValues = this.dynamicFieldsPanel.getFieldValues();
            else this.method.paramValues = Collections.emptyMap();
            if (this.loadedScript != null)
                this.method.credentialsParamNames = this.loadedCredentialParams;
        }

        @Override
        @SuppressWarnings("unchecked")
        public void bindMethod(AuthenticationMethod method)
                throws UnsupportedAuthenticationMethodException {
            this.method = (ClientScriptBasedAuthenticationMethod) method;

            // Make sure the list of scripts is refreshed with just Zest scripts
            List<ScriptWrapper> scripts =
                    getExtensionScript().getScripts(SCRIPT_TYPE_AUTH).stream()
                            .filter(sc -> sc.getEngineName().contains("Zest"))
                            .toList();
            DefaultComboBoxModel<ScriptWrapper> model =
                    new DefaultComboBoxModel<>(scripts.toArray(new ScriptWrapper[scripts.size()]));
            this.scriptsComboBox.setModel(model);
            this.scriptsComboBox.setSelectedItem(this.method.script);
            this.loadScriptButton.setEnabled(this.method.script != null);

            // Load the selected script, if any
            if (this.method.script != null) {
                loadScript(this.method.script, false);
                if (this.dynamicFieldsPanel != null)
                    this.dynamicFieldsPanel.bindFieldValues(this.method.paramValues);
            }
        }

        @Override
        public void bindMethod(
                AuthenticationMethod method, AuthenticationIndicatorsPanel indicatorsPanel)
                throws UnsupportedAuthenticationMethodException {
            this.indicatorsPanel = indicatorsPanel;
            bindMethod(method);
        }

        @Override
        public AuthenticationMethod getMethod() {
            return this.method;
        }

        private void loadScript(ScriptWrapper scriptW, boolean adaptOldValues) {
            AuthenticationScript script = getAuthScriptInterfaceV2(scriptW);
            if (script == null) {
                script = getAuthScriptInterface(scriptW);
            }

            if (script == null) {
                LOGGER.warn(
                        "The script {} does not properly implement the Authentication Script interface.",
                        scriptW.getName());
                warnAndResetPanel(
                        Constant.messages.getString(
                                "authentication.method.script.dialog.error.text.interface",
                                scriptW.getName()));
                return;
            }

            try {
                if (script instanceof AuthenticationScriptV2 scriptV2) {
                    String toolTip =
                            Constant.messages.getString(
                                    "authentication.method.script.dialog.loggedInOutIndicatorsInScript.toolTip");
                    String loggedInIndicator = scriptV2.getLoggedInIndicator();
                    this.method.setLoggedInIndicatorPattern(loggedInIndicator);
                    this.indicatorsPanel.setLoggedInIndicatorPattern(loggedInIndicator);
                    this.indicatorsPanel.setLoggedInIndicatorEnabled(false);
                    this.indicatorsPanel.setLoggedInIndicatorToolTip(toolTip);

                    String loggedOutIndicator = scriptV2.getLoggedOutIndicator();
                    this.method.setLoggedOutIndicatorPattern(loggedOutIndicator);
                    this.indicatorsPanel.setLoggedOutIndicatorPattern(loggedOutIndicator);
                    this.indicatorsPanel.setLoggedOutIndicatorEnabled(false);
                    this.indicatorsPanel.setLoggedOutIndicatorToolTip(toolTip);
                } else {
                    this.indicatorsPanel.setLoggedInIndicatorEnabled(true);
                    this.indicatorsPanel.setLoggedInIndicatorToolTip(null);
                    this.indicatorsPanel.setLoggedOutIndicatorEnabled(true);
                    this.indicatorsPanel.setLoggedOutIndicatorToolTip(null);
                }
                String[] requiredParams = script.getRequiredParamsNames();
                String[] optionalParams = script.getOptionalParamsNames();
                this.loadedCredentialParams = script.getCredentialsParamsNames();
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug(
                            "Loaded authentication script - required parameters: {} - optional parameters: {}",
                            Arrays.toString(requiredParams),
                            Arrays.toString(optionalParams));
                }
                // If there's an already loaded script, make sure we save its values and _try_
                // to place them in the new panel
                Map<String, String> oldValues = null;
                if (adaptOldValues && dynamicFieldsPanel != null) {
                    oldValues = dynamicFieldsPanel.getFieldValues();
                    LOGGER.debug("Trying to adapt old values: {}", oldValues);
                }

                this.dynamicFieldsPanel = new DynamicFieldsPanel(requiredParams, optionalParams);
                this.loadedScript = scriptW;
                if (adaptOldValues && oldValues != null) {
                    this.dynamicFieldsPanel.bindFieldValues(oldValues);
                }

                this.dynamicContentPanel.removeAll();
                this.dynamicContentPanel.add(dynamicFieldsPanel, BorderLayout.CENTER);
                this.dynamicContentPanel.revalidate();

            } catch (Exception e) {
                getExtensionScript().handleScriptException(scriptW, e);
                LOGGER.error("Error while calling authentication script", e);
                warnAndResetPanel(
                        Constant.messages.getString(
                                "authentication.method.script.dialog.error.text.loading",
                                ExceptionUtils.getRootCauseMessage(e)));
            }
        }

        private void warnAndResetPanel(String errorMessage) {
            JOptionPane.showMessageDialog(
                    this,
                    errorMessage,
                    Constant.messages.getString("authentication.method.script.dialog.error.title"),
                    JOptionPane.ERROR_MESSAGE);
            this.loadedScript = null;
            this.scriptsComboBox.setSelectedItem(null);
            this.dynamicFieldsPanel = null;
            this.dynamicContentPanel.removeAll();
            this.dynamicContentPanel.add(new JLabel(LABEL_NOT_LOADED), BorderLayout.CENTER);
            this.dynamicContentPanel.revalidate();
        }
    }

    private ExtensionScript getExtensionScript() {
        if (extensionScript == null)
            extensionScript =
                    Control.getSingleton().getExtensionLoader().getExtension(ExtensionScript.class);
        return extensionScript;
    }

    private AuthenticationScript getAuthScriptInterface(ScriptWrapper script) {
        try {
            return getExtensionScript().getInterface(script, AuthenticationScript.class);
        } catch (Exception e) {
            getExtensionScript()
                    .handleFailedScriptInterface(
                            script,
                            Constant.messages.getString(
                                    "authentication.method.script.dialog.error.text.interface",
                                    script.getName()));
        }
        return null;
    }

    private AuthenticationScriptV2 getAuthScriptInterfaceV2(ScriptWrapper script) {
        try {
            AuthenticationScriptV2 authScript =
                    getExtensionScript().getInterface(script, AuthenticationScriptV2.class);
            if (authScript == null) {
                LOGGER.debug(
                        "Script '{}' is not a AuthenticationScriptV2 interface.", script::getName);
                return null;
            }

            // Some ScriptEngines do not verify if all Interface Methods are contained in the
            // script.
            // So we must invoke them to ensure that they are defined in the loaded script!
            // Otherwise some ScriptEngines loads successfully AuthenticationScriptV2 without the
            // methods getLoggedInIndicator() / getLoggedOutIndicator().
            // Though it should fallback to interface AuthenticationScript.
            authScript.getLoggedInIndicator();
            authScript.getLoggedOutIndicator();
            return authScript;
        } catch (Exception ignore) {
            // The interface is optional, the AuthenticationScript will be checked after this one.
            LOGGER.debug(
                    "Script '{}' is not a AuthenticationScriptV2 interface!",
                    script.getName(),
                    ignore);
        }
        return null;
    }

    @Override
    public void exportData(Configuration config, AuthenticationMethod authMethod) {
        if (!(authMethod instanceof ClientScriptBasedAuthenticationMethod)) {
            throw new UnsupportedAuthenticationMethodException(
                    "Client script based authentication type only supports: "
                            + ClientScriptBasedAuthenticationMethod.class.getName());
        }
        ClientScriptBasedAuthenticationMethod method =
                (ClientScriptBasedAuthenticationMethod) authMethod;
        config.setProperty(CONTEXT_CONFIG_AUTH_SCRIPT_NAME, method.script.getName());
        config.setProperty(
                CONTEXT_CONFIG_AUTH_SCRIPT_PARAMS, EncodingUtils.mapToString(method.paramValues));
    }

    @Override
    public void importData(Configuration config, AuthenticationMethod authMethod)
            throws ConfigurationException {
        if (!(authMethod instanceof ClientScriptBasedAuthenticationMethod)) {
            throw new UnsupportedAuthenticationMethodException(
                    "Client script based authentication type only supports: "
                            + ClientScriptBasedAuthenticationMethod.class.getName());
        }
        ClientScriptBasedAuthenticationMethod method =
                (ClientScriptBasedAuthenticationMethod) authMethod;
        this.loadMethod(
                method,
                objListToStrList(config.getList(CONTEXT_CONFIG_AUTH_SCRIPT_NAME)),
                objListToStrList(config.getList(CONTEXT_CONFIG_AUTH_SCRIPT_PARAMS)));
    }

    private static List<String> objListToStrList(List<Object> oList) {
        List<String> sList = new ArrayList<>(oList.size());
        for (Object o : oList) {
            sList.add(o.toString());
        }
        return sList;
    }

    @Override
    public ApiDynamicActionImplementor getSetMethodForContextApiAction() {
        ApiDynamicActionImplementor impl = super.getSetMethodForContextApiAction();
        impl.setName(API_METHOD_NAME);
        return impl;
    }
}
