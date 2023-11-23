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

import java.awt.EventQueue;
import java.awt.event.KeyEvent;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.swing.ImageIcon;
import org.apache.commons.configuration.Configuration;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.text.StringEscapeUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control.Mode;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.SessionChangedListener;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.authentication.FormBasedAuthenticationMethodType;
import org.zaproxy.zap.authentication.JsonBasedAuthenticationMethodType;
import org.zaproxy.zap.authentication.PostBasedAuthenticationMethodType;
import org.zaproxy.zap.authentication.PostBasedAuthenticationMethodType.PostBasedAuthenticationMethod;
import org.zaproxy.zap.extension.authentication.ExtensionAuthentication;
import org.zaproxy.zap.extension.pscan.ExtensionPassiveScan;
import org.zaproxy.zap.extension.selenium.ExtensionSelenium;
import org.zaproxy.zap.extension.sessions.ExtensionSessionManagement;
import org.zaproxy.zap.extension.users.ExtensionUserManagement;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.utils.Stats;
import org.zaproxy.zap.utils.ZapTextArea;
import org.zaproxy.zap.utils.ZapXmlConfiguration;
import org.zaproxy.zap.view.ZapMenuItem;

public class ExtensionAuthhelper extends ExtensionAdaptor implements SessionChangedListener {

    private Map<Integer, AuthenticationRequestDetails> contextIdToLoginDetails = new HashMap<>();

    private static final Logger LOGGER = LogManager.getLogger(ExtensionAuthhelper.class);

    private static final List<Class<? extends Extension>> EXTENSION_DEPENDENCIES =
            List.of(
                    ExtensionPassiveScan.class,
                    ExtensionSelenium.class,
                    ExtensionUserManagement.class);

    public static final String RESOURCES_DIR = "/org/zaproxy/addon/authhelper/resources/";

    private static final HeaderBasedSessionManagementMethodType HEADER_BASED_SESSION_TYPE =
            new HeaderBasedSessionManagementMethodType();

    protected static final AutoDetectSessionManagementMethodType AUTO_DETECT_SESSION_TYPE =
            new AutoDetectSessionManagementMethodType();

    protected static final BrowserBasedAuthenticationMethodType BROWSER_BASED_AUTH_TYPE =
            new BrowserBasedAuthenticationMethodType();

    private static final AutoDetectAuthenticationMethodType AUTO_DETECT_AUTH_TYPE =
            new AutoDetectAuthenticationMethodType();

    private static final Integer[] HISTORY_TYPES =
            new Integer[] {
                HistoryReference.TYPE_PROXIED, HistoryReference.TYPE_ZAP_USER,
                HistoryReference.TYPE_SPIDER, HistoryReference.TYPE_SPIDER_AJAX,
                HistoryReference.TYPE_AUTHENTICATION
            };

    public static final Set<Integer> HISTORY_TYPES_SET = Set.of(HISTORY_TYPES);

    private ZapMenuItem authTesterMenu;
    private AuthTestDialog authTestDialog;

    private AuthDiagnosticCollector authDiagCollector;
    private AuthhelperParam param;

    public ExtensionAuthhelper() {
        super();
        this.setI18nPrefix("authhelper");
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return EXTENSION_DEPENDENCIES;
    }

    public AuthhelperParam getParam() {
        if (param == null) {
            param = new AuthhelperParam();
        }
        return param;
    }

    @Override
    public void optionsLoaded() {
        ExtensionSessionManagement extSm = AuthUtils.getExtension(ExtensionSessionManagement.class);
        if (extSm != null) {
            extSm.getSessionManagementMethodTypes().add(HEADER_BASED_SESSION_TYPE);
            extSm.getSessionManagementMethodTypes().add(AUTO_DETECT_SESSION_TYPE);
        }
        ExtensionAuthentication extAuth = AuthUtils.getExtension(ExtensionAuthentication.class);
        if (extAuth != null) {
            extAuth.getAuthenticationMethodTypes().add(BROWSER_BASED_AUTH_TYPE);
            extAuth.getAuthenticationMethodTypes().add(AUTO_DETECT_AUTH_TYPE);
        }
    }

    @Override
    public void unload() {
        ExtensionSessionManagement extSm = AuthUtils.getExtension(ExtensionSessionManagement.class);
        if (extSm != null) {
            extSm.getSessionManagementMethodTypes().remove(HEADER_BASED_SESSION_TYPE);
            extSm.getSessionManagementMethodTypes().remove(AUTO_DETECT_SESSION_TYPE);
        }
        ExtensionAuthentication extAuth = AuthUtils.getExtension(ExtensionAuthentication.class);
        if (extAuth != null) {
            extAuth.getAuthenticationMethodTypes().remove(BROWSER_BASED_AUTH_TYPE);
            extAuth.getAuthenticationMethodTypes().remove(AUTO_DETECT_AUTH_TYPE);
        }
        AuthUtils.disableBrowserAuthentication();
        BrowserBasedAuthenticationMethodType.stopProxies();
        AuthUtils.clean();
    }

    @Override
    public void stop() {
        BrowserBasedAuthenticationMethodType.stopProxies();
        AuthUtils.clean();
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        extensionHook.addSessionListener(new AuthSessionChangedListener());
        extensionHook.addOptionsParamSet(getParam());
        if (hasView()) {
            extensionHook.getHookMenu().addToolsMenuItem(getAuthTesterMenu());

            authDiagCollector = new AuthDiagnosticCollector();
            extensionHook.addHttpSenderListener(authDiagCollector);
        }
    }

    @Override
    public String getName() {
        return "ExtensionAuthhelper";
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString("authhelper.name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("authhelper.desc");
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    public void enableAuthDiagCollector(boolean enable) {
        if (this.authDiagCollector != null) {
            this.authDiagCollector.setEnabled(enable);
        }
    }

    public void setAuthDiagCollectorOutput(ZapTextArea output) {
        if (this.authDiagCollector != null) {
            this.authDiagCollector.setCollector(
                    str -> EventQueue.invokeLater(() -> output.append(str)));
        }
    }

    private ZapMenuItem getAuthTesterMenu() {
        if (authTesterMenu == null) {
            authTesterMenu =
                    new ZapMenuItem(
                            "authhelper.topmenu.tools.authtester",
                            View.getSingleton().getMenuShortcutKeyStroke(KeyEvent.VK_T, 0, false));
            authTesterMenu.setIcon(
                    new ImageIcon(
                            this.getClass()
                                    .getResource(RESOURCES_DIR + "images/hand-padlock.png")));

            authTesterMenu.addActionListener(
                    e -> {
                        if (authTestDialog == null) {
                            authTestDialog =
                                    new AuthTestDialog(this, View.getSingleton().getMainFrame());
                        }
                        authTestDialog.setVisible(true);
                    });
        }
        return authTesterMenu;
    }

    private static String urlEncode(String parameter) {
        try {
            return URLEncoder.encode(parameter, "UTF-8");
        } catch (UnsupportedEncodingException ignore) {
            // UTF-8 is one of the standard charsets (see StandardCharsets.UTF_8).
        }
        return parameter;
    }

    private void updateContextAuth(
            Context context, AuthenticationRequestDetails ard, HttpMessage msg) {

        PostBasedAuthenticationMethodType methodType;
        PostBasedAuthenticationMethod method;
        String encodedUserValue;
        String encodedPasswordValue;

        switch (ard.getType()) {
            case JSON:
                methodType = new JsonBasedAuthenticationMethodType();
                encodedUserValue = StringEscapeUtils.escapeJson(ard.getUserParam().getValue());
                encodedPasswordValue =
                        StringEscapeUtils.escapeJson(ard.getPasswordParam().getValue());
                Stats.incCounter("stats.auth.configure.auth.json");
                break;
            case FORM:
            default:
                methodType = new FormBasedAuthenticationMethodType();
                encodedUserValue = urlEncode(ard.getUserParam().getValue());
                encodedPasswordValue = urlEncode(ard.getPasswordParam().getValue());
                Stats.incCounter("stats.auth.configure.auth.form");
                break;
        }
        try {
            method = methodType.createAuthenticationMethod(context.getId());
            Configuration config = new ZapXmlConfiguration();
            config.setProperty("context.authentication.form.loginurl", ard.getUri().toString());
            config.setProperty(
                    "context.authentication.form.loginbody",
                    msg.getRequestBody()
                            .toString()
                            .replace(
                                    encodedUserValue,
                                    PostBasedAuthenticationMethod.MSG_USER_PATTERN)
                            .replace(
                                    encodedPasswordValue,
                                    PostBasedAuthenticationMethod.MSG_PASS_PATTERN));
            if (StringUtils.isEmpty(ard.getReferer())) {
                config.setProperty(
                        "context.authentication.form.loginpageurl", ard.getUri().toString());
            } else {
                config.setProperty("context.authentication.form.loginpageurl", ard.getReferer());
            }
            methodType.importData(config, method);
            context.setAuthenticationMethod(method);
            context.save();
        } catch (Exception e) {
            LOGGER.error("Failed to set authentication method", e);
            Stats.incCounter("stats.auth.configure.auth.error");
        }
    }

    public void registerAuthRequest(AuthenticationRequestDetails lrd, HttpMessage msg) {
        List<Context> contextList =
                getModel().getSession().getContextsForUrl(lrd.getUri().toString());
        for (Context context : contextList) {
            AuthenticationRequestDetails details = contextIdToLoginDetails.get(context.getId());
            if (details != null) {
                // We have already found a login request, but this one might be better?
                if (lrd.getConfidence() > details.getConfidence()) {
                    updateContextAuth(context, lrd, msg);
                }
            } else if (context.getAuthenticationMethod().getType()
                    instanceof AutoDetectAuthenticationMethodType) {
                contextIdToLoginDetails.put(context.getId(), lrd);
                updateContextAuth(context, lrd, msg);
            }
        }
    }

    private class AuthSessionChangedListener implements SessionChangedListener {

        @Override
        public void sessionChanged(Session session) {
            contextIdToLoginDetails.clear();
        }

        @Override
        public void sessionAboutToChange(Session session) {}

        @Override
        public void sessionScopeChanged(Session session) {}

        @Override
        public void sessionModeChanged(Mode mode) {}
    }

    @Override
    public void sessionChanged(Session session) {
        AuthUtils.clean();
    }

    @Override
    public void sessionAboutToChange(Session session) {
        BrowserBasedAuthenticationMethodType.stopProxies();
        if (this.authDiagCollector != null) {
            this.authDiagCollector.reset();
        }
    }

    @Override
    public void sessionScopeChanged(Session session) {
        // Ignore
    }

    @Override
    public void sessionModeChanged(Mode mode) {
        // Ignore
    }
}
