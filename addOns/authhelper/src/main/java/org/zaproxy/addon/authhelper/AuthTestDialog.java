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

import java.awt.Frame;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.io.File;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import javax.swing.BorderFactory;
import javax.swing.Icon;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import org.apache.commons.configuration.Configuration;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.httpclient.URI;
import org.apache.commons.lang3.StringUtils;
import org.openqa.selenium.WebDriver;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.authhelper.AutoDetectSessionManagementMethodType.AutoDetectSessionManagementMethod;
import org.zaproxy.addon.authhelper.BrowserBasedAuthenticationMethodType.BrowserBasedAuthenticationMethod;
import org.zaproxy.addon.authhelper.ClientScriptBasedAuthenticationMethodType.ClientScriptBasedAuthenticationMethod;
import org.zaproxy.addon.authhelper.internal.AuthenticationBrowserHook;
import org.zaproxy.addon.authhelper.internal.AuthenticationStep;
import org.zaproxy.addon.authhelper.internal.StepsPanel;
import org.zaproxy.addon.commonlib.internal.TotpSupport;
import org.zaproxy.addon.pscan.ExtensionPassiveScan2;
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.authentication.AuthenticationMethod;
import org.zaproxy.zap.authentication.AuthenticationMethod.AuthCheckingStrategy;
import org.zaproxy.zap.authentication.AuthenticationMethodType;
import org.zaproxy.zap.authentication.GenericAuthenticationCredentials;
import org.zaproxy.zap.authentication.ScriptBasedAuthenticationMethodType;
import org.zaproxy.zap.authentication.UsernamePasswordAuthenticationCredentials;
import org.zaproxy.zap.extension.authentication.ExtensionAuthentication;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.selenium.BrowserHook;
import org.zaproxy.zap.extension.selenium.BrowserUI;
import org.zaproxy.zap.extension.selenium.BrowsersComboBoxModel;
import org.zaproxy.zap.extension.selenium.ExtensionSelenium;
import org.zaproxy.zap.extension.users.ExtensionUserManagement;
import org.zaproxy.zap.extension.zest.ExtensionZest;
import org.zaproxy.zap.extension.zest.ZestAuthenticationRunner;
import org.zaproxy.zap.extension.zest.ZestScriptWrapper;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.model.SessionStructure;
import org.zaproxy.zap.session.SessionManagementMethod;
import org.zaproxy.zap.session.SessionManagementMethodType;
import org.zaproxy.zap.users.User;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.utils.FontUtils;
import org.zaproxy.zap.utils.FontUtils.Size;
import org.zaproxy.zap.utils.Stats;
import org.zaproxy.zap.utils.StatsListener;
import org.zaproxy.zap.utils.ZapTextArea;
import org.zaproxy.zap.utils.ZapTextField;
import org.zaproxy.zap.utils.ZapXmlConfiguration;
import org.zaproxy.zap.view.LayoutHelper;
import org.zaproxy.zap.view.StandardFieldsDialog;
import org.zaproxy.zest.core.v1.ZestScript;
import org.zaproxy.zest.impl.ZestScriptEngineFactory;

@SuppressWarnings("serial")
public class AuthTestDialog extends StandardFieldsDialog {

    private static final long serialVersionUID = 1L;

    private static final String CONTEXT_LABEL = "authhelper.auth.test.dialog.label.context";
    private static final String LOGIN_URL_LABEL = "authhelper.auth.test.dialog.label.loginurl";
    private static final String METHOD_LABEL = "authhelper.auth.test.dialog.label.method";
    private static final String SCRIPT_LABEL = "authhelper.auth.test.dialog.label.script";
    private static final String PASSWORD_LABEL = "authhelper.auth.test.dialog.label.password";
    private static final String USERNAME_LABEL = "authhelper.auth.test.dialog.label.username";
    private static final String BROWSER_LABEL = "authhelper.auth.test.dialog.label.browser";
    private static final String LOGIN_WAIT_LABEL = "authhelper.auth.test.dialog.label.wait";
    private static final String STEP_DELAY_LABEL = "authhelper.auth.test.dialog.label.stepdelay";
    private static final String RECORD_DIAGNOSTICS_LABEL =
            "authhelper.auth.test.dialog.label.recdiag";
    private static final String DIAGNOSTICS_LABEL = "authhelper.auth.test.dialog.label.diag";
    private static final String DOMAINS_LABEL = "authhelper.auth.test.dialog.label.domains";
    private static final String COPY_LABEL = "authhelper.auth.test.dialog.label.copy";

    private static final String FOUND_STR =
            Constant.messages.getString("authhelper.auth.test.dialog.results.found");
    private static final String METHOD_BROWSER_STR =
            Constant.messages.getString("authhelper.auth.test.dialog.label.method.browser");
    private static final String METHOD_SCRIPT_STR =
            Constant.messages.getString("authhelper.auth.test.dialog.label.method.script");

    private static final ImageIcon GREY_BALL =
            DisplayUtils.getScaledIcon(ZAP.class.getResource("/resource/icon/16/159.png"));
    private static final Icon GREEN_BALL =
            DisplayUtils.getScaledIcon(ZAP.class.getResource("/resource/icon/16/152.png"));
    private static final Icon RED_BALL =
            DisplayUtils.getScaledIcon(ZAP.class.getResource("/resource/icon/16/151.png"));
    private static final Icon YELLOW_BALL =
            DisplayUtils.getScaledIcon(ZAP.class.getResource("/resource/icon/16/154.png"));

    private String DEFAULT_SCRIPT_CREDS = "not-currently-used";

    private JPanel resultsPanel;
    private JLabel usernameFieldLabel = new JLabel();
    private JLabel passwordFieldLabel = new JLabel();
    private JLabel statusLabel = new JLabel();
    private JLabel sessionIdLabel = new JLabel();
    private JLabel verifIdLabel = new JLabel();
    private JButton[] extraButtons;
    private JComboBox<String> scriptField;
    private JButton recordButton;

    private List<String> scriptNames;

    private StepsPanel stepsPanel;

    private ZapTextArea diagnosticField;
    private Boolean usernameFieldFound;
    private Boolean passwordFieldFound;

    private BrowsersComboBoxModel browserComboModel;

    private ExtensionAuthhelper ext;
    private ExtensionScript extensionScript;

    public AuthTestDialog(ExtensionAuthhelper ext, Frame owner) {
        super(
                owner,
                "authhelper.auth.test.dialog.title",
                DisplayUtils.getScaledDimension(600, 550),
                new String[] {
                    "authhelper.auth.test.dialog.tab.test",
                    "authhelper.auth.test.dialog.tab.domains",
                    "authhelper.auth.test.dialog.tab.steps",
                    "authhelper.auth.test.dialog.tab.diag"
                });

        this.ext = ext;
        AuthhelperParam params = this.ext.getParam();

        this.addTargetSelectField(0, LOGIN_URL_LABEL, null, true, false);
        this.addTextField(
                0,
                CONTEXT_LABEL,
                Constant.messages.getString("authhelper.auth.test.dialog.default-context"));

        extensionScript =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionScript.class);

        if (isClientScriptSupported()) {
            this.addComboField(
                    0,
                    METHOD_LABEL,
                    new String[] {METHOD_BROWSER_STR, METHOD_SCRIPT_STR},
                    METHOD_BROWSER_STR);
            this.addFieldListener(METHOD_LABEL, e -> setMethodState());
        } else {
            this.addComboField(
                    0, METHOD_LABEL, new String[] {METHOD_BROWSER_STR}, METHOD_BROWSER_STR);
        }

        scriptField = new JComboBox<>();
        setScriptNames();
        recordButton =
                new JButton(
                        Constant.messages.getString("authhelper.auth.test.dialog.button.record"));
        recordButton.addActionListener(
                l -> {
                    String url = this.getStringValue(LOGIN_URL_LABEL).toLowerCase(Locale.ROOT);
                    if (url.isBlank()) {
                        View.getSingleton()
                                .showWarningDialog(
                                        AuthTestDialog.this,
                                        Constant.messages.getString(
                                                "authhelper.auth.test.dialog.error.nourl"));
                        return;
                    }
                    ExtensionZest extZest = AuthUtils.getExtension(ExtensionZest.class);

                    ScriptWrapper sw = new ScriptWrapper();
                    sw.setEngine(extZest.getZestEngineWrapper());
                    sw.setEngineName(ZestScriptEngineFactory.NAME);
                    sw.setType(
                            extensionScript.getScriptType(
                                    ScriptBasedAuthenticationMethodType.SCRIPT_TYPE_AUTH));
                    ZestScriptWrapper scriptWrapper = new ZestScriptWrapper(sw);

                    ZestScript script = scriptWrapper.getZestScript();

                    script.setTitle(this.getScriptName(url));
                    scriptWrapper.setName(script.getTitle());
                    scriptWrapper.setContents(extZest.convertElementToString(script));
                    scriptWrapper.setLoadOnStart(true);

                    ScriptNode scriptNode = extZest.add(scriptWrapper, false, false);
                    extZest.updated(scriptNode, false);
                    extZest.setRecordingNode(scriptNode);

                    extZest.startClientRecording(
                            scriptNode, browserComboModel.getSelectedItem().getName(), url);
                    setScriptNames();
                });

        this.addCustomComponent(0, SCRIPT_LABEL, getSideBySidePanel(scriptField, recordButton));

        ExtensionSelenium extSel =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionSelenium.class);

        browserComboModel = extSel.createBrowsersComboBoxModel();
        browserComboModel.setSelectedBrowser(params.getBrowser());
        this.addComboField(0, BROWSER_LABEL, browserComboModel);

        this.addTextField(0, USERNAME_LABEL, params.getUsername());
        this.addPasswordField(0, PASSWORD_LABEL, "");
        this.addNumberField(0, LOGIN_WAIT_LABEL, 0, Integer.MAX_VALUE, params.getWait());
        this.addNumberField(0, STEP_DELAY_LABEL, 0, Integer.MAX_VALUE, params.getStepDelay());
        this.addCheckBoxField(0, RECORD_DIAGNOSTICS_LABEL, params.isRecordDiagnostics());
        this.addCustomComponent(0, getResultsPanel());
        this.addPadding(0);

        int tab = 1;

        addMultilineField(tab, DOMAINS_LABEL, params.getDomains());

        tab++;
        stepsPanel = new StepsPanel(this, true);
        stepsPanel.setSteps(params.getSteps());
        setCustomTabPanel(tab, stepsPanel.getPanel());

        tab++;
        addMultilineField(tab, DIAGNOSTICS_LABEL, "");
        diagnosticField = (ZapTextArea) this.getField(DIAGNOSTICS_LABEL);
        diagnosticField.setEditable(false);
        ext.setAuthDiagCollectorOutput(diagnosticField);

        JPanel buttonPanel = new JPanel();
        buttonPanel.setLayout(new GridBagLayout());
        JButton copyButton =
                new JButton(Constant.messages.getString("authhelper.auth.test.dialog.button.copy"));
        copyButton.addActionListener(
                l ->
                        Toolkit.getDefaultToolkit()
                                .getSystemClipboard()
                                .setContents(new StringSelection(diagnosticField.getText()), null));

        buttonPanel.add(new JLabel(), LayoutHelper.getGBC(0, 0, 1, 0.3D));
        buttonPanel.add(copyButton, LayoutHelper.getGBC(1, 0, 1, 0.3D));
        buttonPanel.add(new JLabel(), LayoutHelper.getGBC(2, 0, 1, 0.3D));

        addCustomComponent(tab, COPY_LABEL, buttonPanel);

        ZapTextField text = (ZapTextField) this.getField(LOGIN_URL_LABEL);
        text.setText(params.getLoginUrl());
        setMethodState();

        this.setHideOnSave(false);
        this.pack();
    }

    private String getScriptName(String urlStr) {
        String base = urlStr;
        try {
            URI url = new URI(urlStr, true);
            base = url.getHost();
        } catch (Exception e) {
            // Ignore
        }
        String scriptName = base;
        if (scriptNames != null) {
            int i = 2;
            while (scriptNames.contains(scriptName)) {
                scriptName = base + i++;
            }
        }
        return scriptName;
    }

    /**
     * Sets the names of the valid scripts in the Client Script Field. It will select the first
     * "new" script that it finds, on the basis that this is likely to be the one the user has just
     * started recording.
     */
    private void setScriptNames() {
        List<String> prevNames = scriptNames;
        scriptField.removeAllItems();
        List<ScriptWrapper> scripts =
                extensionScript.getScripts(ScriptBasedAuthenticationMethodType.SCRIPT_TYPE_AUTH);
        scriptNames =
                scripts.stream()
                        .filter(s -> s.getEngineName().contains("Zest"))
                        .map(ScriptWrapper::getName)
                        .toList();
        for (String script : scriptNames) {
            scriptField.addItem(script);
        }
        if (prevNames != null && prevNames.size() > 0) {
            for (String script : scriptNames) {
                if (!prevNames.contains(script)) {
                    scriptField.setSelectedItem(script);
                    break;
                }
            }
        }
    }

    private void setMethodState() {
        boolean isBrowserAuth = isBrowserAuth();

        scriptField.setEnabled(!isBrowserAuth);
        recordButton.setEnabled(!isBrowserAuth);
        this.getField(PASSWORD_LABEL).setEnabled(isBrowserAuth);
        this.getField(USERNAME_LABEL).setEnabled(isBrowserAuth);
        this.getField(STEP_DELAY_LABEL).setEnabled(isBrowserAuth);
    }

    @Override
    public String getHelpIndex() {
        return "authhelper.auth-tester";
    }

    private JPanel getResultsPanel() {
        if (resultsPanel == null) {
            resultsPanel = new JPanel();
            resultsPanel.setLayout(new GridBagLayout());
            resultsPanel.setBorder(BorderFactory.createTitledBorder("Results"));
            JLabel status =
                    new JLabel(
                            Constant.messages.getString(
                                    "authhelper.auth.test.dialog.results.status"));
            statusLabel.setFont(FontUtils.getFont(Size.larger));
            status.setFont(FontUtils.getFont(Size.larger));

            int y = 0;
            int scaledSize = DisplayUtils.getScaledSize(4);
            Insets insets = new Insets(scaledSize, scaledSize, scaledSize, scaledSize);
            resultsPanel.add(status, LayoutHelper.getGBC(0, y, 1, 1L, insets));
            resultsPanel.add(statusLabel, LayoutHelper.getGBC(1, y++, 1, 1L, insets));
            resultsPanel.add(
                    new JLabel(
                            Constant.messages.getString(
                                    "authhelper.auth.test.dialog.results.username")),
                    LayoutHelper.getGBC(0, y, 1, 1L, insets));
            resultsPanel.add(usernameFieldLabel, LayoutHelper.getGBC(1, y++, 1, 1L, insets));
            resultsPanel.add(
                    new JLabel(
                            Constant.messages.getString(
                                    "authhelper.auth.test.dialog.results.password")),
                    LayoutHelper.getGBC(0, y, 1, 1L, insets));
            resultsPanel.add(passwordFieldLabel, LayoutHelper.getGBC(1, y++, 1, 1L, insets));
            resultsPanel.add(
                    new JLabel(
                            Constant.messages.getString(
                                    "authhelper.auth.test.dialog.results.session")),
                    LayoutHelper.getGBC(0, y, 1, 1L, insets));
            resultsPanel.add(sessionIdLabel, LayoutHelper.getGBC(1, y++, 1, 1L, insets));
            resultsPanel.add(
                    new JLabel(
                            Constant.messages.getString(
                                    "authhelper.auth.test.dialog.results.verif")),
                    LayoutHelper.getGBC(0, y, 1, 1L, insets));
            resultsPanel.add(verifIdLabel, LayoutHelper.getGBC(1, y++, 1, 1L, insets));
            resetResultsPanel();
        }
        return resultsPanel;
    }

    private void resetResultsPanel() {
        statusLabel.setText(
                Constant.messages.getString("authhelper.auth.test.dialog.status.notstarted"));
        statusLabel.setIcon(GREY_BALL);
        usernameFieldLabel.setText("");
        usernameFieldLabel.setIcon(GREY_BALL);
        passwordFieldLabel.setText("");
        passwordFieldLabel.setIcon(GREY_BALL);
        sessionIdLabel.setText("");
        sessionIdLabel.setIcon(GREY_BALL);
        verifIdLabel.setText("");
        verifIdLabel.setIcon(GREY_BALL);
    }

    private boolean isBrowserAuth() {
        return this.getStringValue(METHOD_LABEL).equals(METHOD_BROWSER_STR);
    }

    private boolean isClientScriptSupported() {
        ExtensionAuthentication extAuth =
                Control.getSingleton()
                        .getExtensionLoader()
                        .getExtension(ExtensionAuthentication.class);
        return extAuth.getAuthenticationMethodTypeForIdentifier(8) != null;
    }

    private ClientScriptBasedAuthenticationMethod getClientAuthMethod() {
        ExtensionAuthentication extAuth =
                Control.getSingleton()
                        .getExtensionLoader()
                        .getExtension(ExtensionAuthentication.class);
        ClientScriptBasedAuthenticationMethodType clientScriptType =
                (ClientScriptBasedAuthenticationMethodType)
                        extAuth.getAuthenticationMethodTypeForIdentifier(8);
        return clientScriptType.createAuthenticationMethod(0);
    }

    private void authenticate() {
        StatsListener statsListener = null;
        try {
            String username = this.getStringValue(USERNAME_LABEL);
            String password = this.getStringValue(PASSWORD_LABEL);

            this.diagnosticField.setText("");
            ext.enableAuthDiagCollector(true);
            ext.setAuthDiagCollectorCredentials(username, password);

            // Delete the context if it already exists
            Session session = Model.getSingleton().getSession();
            String contextName = this.getStringValue(CONTEXT_LABEL);
            Context context = session.getContext(contextName);
            if (context != null) {
                session.deleteContext(context);
            }
            // Create the context
            statusLabel.setText("Creating context");
            context = Model.getSingleton().getSession().getNewContext(contextName);
            String loginUrl = this.getStringValue(LOGIN_URL_LABEL);
            context.addIncludeInContextRegex(
                    SessionStructure.getHostName(new URI(loginUrl, false)) + ".*");

            for (String dom : getDomains()) {
                if (dom.endsWith(".*")) {
                    // Just in case the user has added this anyway
                    dom = dom.substring(0, dom.length() - 2);
                }
                context.addIncludeInContextRegex(dom + ".*");
            }

            JComboBox<?> browserCombo = (JComboBox<?>) this.getField(BROWSER_LABEL);
            String browserId = ((BrowserUI) browserCombo.getSelectedItem()).getBrowser().getId();

            AuthenticationMethod am;
            User user;
            if (isBrowserAuth()) {
                BrowserBasedAuthenticationMethod bam =
                        ExtensionAuthhelper.BROWSER_BASED_AUTH_TYPE.createAuthenticationMethod(
                                context.getId());
                bam.setLoginPageUrl(loginUrl);
                bam.setDiagnostics(getBoolValue(RECORD_DIAGNOSTICS_LABEL));

                bam.setBrowserId(browserId);
                bam.setLoginPageWait(this.getIntValue(LOGIN_WAIT_LABEL));
                bam.setStepDelay(this.getIntValue(STEP_DELAY_LABEL));
                bam.setAuthenticationSteps(
                        stepsPanel.getSteps().stream()
                                .filter(AuthenticationStep::isEnabled)
                                .toList());
                reloadAuthenticationMethod(bam);
                context.setAuthenticationMethod(bam);
                am = bam;

                // Set up user
                user = new User(context.getId(), username);
                UsernamePasswordAuthenticationCredentials upCreds =
                        TotpSupport.createUsernamePasswordAuthenticationCredentials(
                                am, username, password);
                setTotp(stepsPanel.getSteps(), upCreds);
                user.setAuthenticationCredentials(upCreds);

            } else {
                ClientScriptBasedAuthenticationMethod csam = getClientAuthMethod();

                ScriptWrapper scriptWrapper =
                        extensionScript.getScript((String) scriptField.getSelectedItem());
                if (scriptWrapper.getFile() == null) {
                    // Newly recorded, but we need it to have been saved
                    File f =
                            Paths.get(
                                            Constant.getZapHome(),
                                            ExtensionScript.SCRIPTS_DIR,
                                            ExtensionScript.SCRIPTS_DIR,
                                            scriptWrapper.getTypeName(),
                                            scriptWrapper.getName() + ".zst")
                                    .toFile();
                    scriptWrapper.setFile(f);
                    extensionScript.saveScript(scriptWrapper);
                }
                csam.setScriptWrapper(scriptWrapper);
                csam.setDiagnostics(getBoolValue(RECORD_DIAGNOSTICS_LABEL));
                csam.setLoginPageWait(this.getIntValue(LOGIN_WAIT_LABEL));

                // TODO this is needed due to a core bug
                Map<String, String> map = new HashMap<>();
                map.put("script", scriptWrapper.getFile().getAbsolutePath());
                map.put("scriptEngine", scriptWrapper.getEngineName());
                csam.setParamValues(map);

                reloadAuthenticationMethod(csam);
                context.setAuthenticationMethod(csam);
                am = csam;

                // Set up user
                user = new User(context.getId(), DEFAULT_SCRIPT_CREDS);
                GenericAuthenticationCredentials genCreds =
                        new GenericAuthenticationCredentials(
                                new String[] {
                                    ZestAuthenticationRunner.USERNAME,
                                    ZestAuthenticationRunner.PASSWORD
                                });
                genCreds.setParam(ZestAuthenticationRunner.USERNAME, DEFAULT_SCRIPT_CREDS);
                genCreds.setParam(ZestAuthenticationRunner.PASSWORD, DEFAULT_SCRIPT_CREDS);

                user.setAuthenticationCredentials(genCreds);
            }

            user.setEnabled(true);
            Control.getSingleton()
                    .getExtensionLoader()
                    .getExtension(ExtensionUserManagement.class)
                    .getContextUserAuthManager(context.getId())
                    .addUser(user);

            // Set up session auto-detection
            AutoDetectSessionManagementMethod sm =
                    ExtensionAuthhelper.AUTO_DETECT_SESSION_TYPE.createSessionManagementMethod(
                            context.getId());
            context.setSessionManagementMethod(sm);
            reloadSessionManagementMethod(sm);

            // Set up verification auto-detection
            try {
                am.setAuthCheckingStrategy(AuthCheckingStrategy.valueOf("AUTO_DETECT"));
            } catch (Exception e) {
                // Ignore - not yet supported so will default to "poll"
            }

            statusLabel.setText(
                    Constant.messages.getString("authhelper.auth.test.dialog.status.launching"));
            statusLabel.setIcon(YELLOW_BALL);
            ExtensionSelenium extSel =
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionSelenium.class);

            // Assume they will work as we only gets stats on failure
            usernameFieldFound = true;
            passwordFieldFound = true;

            statsListener =
                    new DefaultStatsListener() {

                        @Override
                        public void counterInc(String site, String key) {
                            if (AuthUtils.AUTH_NO_USER_FIELD_STATS.equals(key)) {
                                usernameFieldFound = false;
                            }
                            if (AuthUtils.AUTH_NO_PASSWORD_FIELD_STATS.equals(key)) {
                                passwordFieldFound = false;
                            }
                            if (AuthUtils.AUTH_FOUND_FIELDS_STATS.equals(key)) {
                                usernameFieldFound = true;
                                passwordFieldFound = true;
                            }
                        }
                    };
            Stats.addListener(statsListener);

            WebDriver wd = null;
            BrowserHook clientBrowserHook = null;
            try {
                try {
                    if (isBrowserAuth()) {
                        AuthUtils.enableBrowserAuthentication(context, username);
                    } else {
                        clientBrowserHook = new AuthenticationBrowserHook(context, user);
                        AuthUtils.getExtension(ExtensionSelenium.class)
                                .registerBrowserHook(clientBrowserHook);
                    }
                } catch (Exception e) {
                    // Must be already set, not a real problem
                }
                wd = extSel.getProxiedBrowser(browserId);
            } finally {
                if (isBrowserAuth()) {
                    AuthUtils.disableBrowserAuthentication();
                } else if (clientBrowserHook != null) {
                    AuthUtils.getExtension(ExtensionSelenium.class)
                            .deregisterBrowserHook(clientBrowserHook);
                }

                if (wd != null) {
                    wd.quit();
                }
            }
            context = session.getContext(contextName);
            ExtensionPassiveScan2 extPscan =
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionPassiveScan2.class);

            int count = 0;
            int score = 0;

            do {
                count += 1;
                if (count > 20) {
                    break;
                }
                if (!(context.getSessionManagementMethod()
                        instanceof AutoDetectSessionManagementMethod)) {
                    sessionIdLabel.setText(FOUND_STR);
                    sessionIdLabel.setIcon(GREEN_BALL);
                    score++;
                }
                if (StringUtils.isNotBlank(context.getAuthenticationMethod().getPollUrl())) {
                    verifIdLabel.setText(FOUND_STR);
                    verifIdLabel.setIcon(GREEN_BALL);
                    score++;
                }
                if (StringUtils.isBlank(usernameFieldLabel.getText())
                        && Boolean.TRUE.equals(usernameFieldFound)) {
                    usernameFieldLabel.setText(FOUND_STR);
                    usernameFieldLabel.setIcon(GREEN_BALL);
                    score++;
                }
                if (StringUtils.isBlank(passwordFieldLabel.getText())
                        && Boolean.TRUE.equals(passwordFieldFound)) {
                    passwordFieldLabel.setText(FOUND_STR);
                    passwordFieldLabel.setIcon(GREEN_BALL);
                    score++;
                }

                if (score >= 4) {
                    break;
                }
                try {
                    Thread.sleep(500);
                } catch (InterruptedException e) {
                    // Ignore
                }
            } while (extPscan.getRecordsToScan() > 0);

            if (score >= 4) {
                statusLabel.setText(
                        Constant.messages.getString("authhelper.auth.test.dialog.status.passed"));
                statusLabel.setIcon(GREEN_BALL);
            } else {
                statusLabel.setText(
                        Constant.messages.getString("authhelper.auth.test.dialog.status.failed"));
                statusLabel.setIcon(RED_BALL);
            }

        } catch (Exception e) {
            View.getSingleton().showWarningDialog(this, e.getMessage());
        } finally {
            if (statsListener != null) {
                Stats.removeListener(statsListener);
            }
            ext.enableAuthDiagCollector(false);
        }
    }

    private List<String> getDomains() {
        return List.of(this.getStringValue(DOMAINS_LABEL).split("\r?\n")).stream()
                .filter(StringUtils::isNotBlank)
                .toList();
    }

    private static void setTotp(
            List<AuthenticationStep> steps, UsernamePasswordAuthenticationCredentials credentials) {
        if (!TotpSupport.isTotpInCore()) {
            return;
        }

        Optional<AuthenticationStep> optStep =
                steps.stream()
                        .filter(e -> e.getType() == AuthenticationStep.Type.TOTP_FIELD)
                        .findFirst();
        if (optStep.isEmpty()) {
            return;
        }

        AuthenticationStep totpStep = optStep.get();
        TotpSupport.TotpData totpData =
                new TotpSupport.TotpData(
                        totpStep.getTotpSecret(),
                        totpStep.getTotpPeriod(),
                        totpStep.getTotpDigits(),
                        totpStep.getTotpAlgorithm());
        TotpSupport.setTotpData(totpData, credentials);
    }

    private static void reloadAuthenticationMethod(AuthenticationMethod am)
            throws ConfigurationException {
        // OK, this does look weird, but it is the easiest way to actually get
        // the session management data loaded :/
        AuthenticationMethodType type = am.getType();
        Configuration config = new ZapXmlConfiguration();
        type.exportData(config, am);
        type.importData(config, am);
    }

    private static void reloadSessionManagementMethod(SessionManagementMethod smm)
            throws ConfigurationException {
        // OK, this does look weird, but it is the easiest way to actually get
        // the session management data loaded :/
        SessionManagementMethodType type = smm.getType();
        Configuration config = new ZapXmlConfiguration();
        type.exportData(config, smm);
        type.importData(config, smm);
    }

    @Override
    public String getSaveButtonText() {
        return Constant.messages.getString("authhelper.auth.test.dialog.button.save");
    }

    @Override
    public JButton[] getExtraButtons() {
        if (extraButtons == null) {
            JButton resetButton =
                    new JButton(
                            Constant.messages.getString(
                                    "authhelper.auth.test.dialog.button.reset"));
            resetButton.addActionListener(
                    e -> {
                        ((JTextField) getField(CONTEXT_LABEL))
                                .setText(
                                        Constant.messages.getString(
                                                "authhelper.auth.test.dialog.default-context"));
                        setFieldValue(LOGIN_URL_LABEL, "");
                        setFieldValue(DOMAINS_LABEL, "");
                        setFieldValue(USERNAME_LABEL, "");
                        setFieldValue(PASSWORD_LABEL, "");
                        setFieldValue(LOGIN_WAIT_LABEL, AuthhelperParam.DEFAULT_WAIT);
                        setFieldValue(STEP_DELAY_LABEL, 0);
                        browserComboModel.setSelectedBrowser(AuthhelperParam.DEFAULT_BROWSER);
                        setFieldValue(RECORD_DIAGNOSTICS_LABEL, false);
                        stepsPanel.getSteps().forEach(step -> step.setEnabled(false));

                        resetResultsPanel();
                        diagnosticField.setText("");

                        this.saveDetails();
                    });

            extraButtons = new JButton[] {resetButton};
        }
        return extraButtons;
    }

    @Override
    public void save() {
        resetResultsPanel();
        Thread t = new Thread(this::authenticate, "ZAP-auth-tester");
        t.start();
        // Save the values for next time
        this.saveDetails();
    }

    private void saveDetails() {
        AuthhelperParam params = this.ext.getParam();
        params.setLoginUrl(this.getStringValue(LOGIN_URL_LABEL));
        params.setDomains(this.getStringValue(DOMAINS_LABEL));
        params.setUsername(this.getStringValue(USERNAME_LABEL));
        JComboBox<?> browserCombo = (JComboBox<?>) this.getField(BROWSER_LABEL);
        params.setBrowser(((BrowserUI) browserCombo.getSelectedItem()).getBrowser().getId());
        params.setWait(this.getIntValue(LOGIN_WAIT_LABEL));
        params.setStepDelay(this.getIntValue(STEP_DELAY_LABEL));
        params.setRecordDiagnostics(getBoolValue(RECORD_DIAGNOSTICS_LABEL));
        params.setSteps(stepsPanel.getSteps());
    }

    @Override
    public String validateFields() {
        String url = this.getStringValue(LOGIN_URL_LABEL).toLowerCase(Locale.ROOT);
        if (url.isBlank()) {
            return Constant.messages.getString("authhelper.auth.test.dialog.error.nourl");
        }
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            return Constant.messages.getString("authhelper.auth.test.dialog.error.badurl");
        }
        if (this.getStringValue(CONTEXT_LABEL).isBlank()) {
            return Constant.messages.getString("authhelper.auth.test.dialog.error.nocontext");
        }
        if (this.isBrowserAuth()) {
            if (this.getStringValue(USERNAME_LABEL).isBlank()) {
                return Constant.messages.getString("authhelper.auth.test.dialog.error.nouser");
            }
            if (this.getStringValue(PASSWORD_LABEL).isBlank()) {
                return Constant.messages.getString("authhelper.auth.test.dialog.error.nopassword");
            }
        }
        for (String dom : this.getDomains()) {
            String domLc = dom.toLowerCase(Locale.ROOT);
            if (!domLc.startsWith("http://") && !domLc.startsWith("https://")) {
                return Constant.messages.getString("authhelper.auth.test.dialog.error.baddom", dom);
            }
            try {
                new URI(dom, false);
            } catch (Exception e) {
                return Constant.messages.getString("authhelper.auth.test.dialog.error.baddom", dom);
            }
        }
        return null;
    }

    private static class DefaultStatsListener implements StatsListener {

        @Override
        public void counterInc(String key) {
            // Ignore
        }

        @Override
        public void counterInc(String site, String key) {
            // Ignore
        }

        @Override
        public void counterInc(String key, long inc) {
            // Ignore
        }

        @Override
        public void counterInc(String site, String key, long inc) {
            // Ignore
        }

        @Override
        public void counterDec(String key) {
            // Ignore
        }

        @Override
        public void counterDec(String site, String key) {
            // Ignore
        }

        @Override
        public void counterDec(String key, long dec) {
            // Ignore
        }

        @Override
        public void counterDec(String site, String key, long dec) {
            // Ignore
        }

        @Override
        public void highwaterMarkSet(String key, long value) {
            // Ignore
        }

        @Override
        public void highwaterMarkSet(String site, String key, long value) {
            // Ignore
        }

        @Override
        public void lowwaterMarkSet(String key, long value) {
            // Ignore
        }

        @Override
        public void lowwaterMarkSet(String site, String key, long value) {
            // Ignore
        }

        @Override
        public void allCleared() {
            // Ignore
        }

        @Override
        public void allCleared(String site) {
            // Ignore
        }

        @Override
        public void cleared(String keyPrefix) {
            // Ignore
        }

        @Override
        public void cleared(String site, String keyPrefix) {
            // Ignore
        }
    }
}
