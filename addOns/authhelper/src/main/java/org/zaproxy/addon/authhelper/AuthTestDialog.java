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
import javax.swing.BorderFactory;
import javax.swing.Icon;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
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
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.authentication.AuthenticationMethod;
import org.zaproxy.zap.authentication.AuthenticationMethod.AuthCheckingStrategy;
import org.zaproxy.zap.authentication.AuthenticationMethodType;
import org.zaproxy.zap.authentication.UsernamePasswordAuthenticationCredentials;
import org.zaproxy.zap.extension.pscan.ExtensionPassiveScan;
import org.zaproxy.zap.extension.selenium.BrowserUI;
import org.zaproxy.zap.extension.selenium.BrowsersComboBoxModel;
import org.zaproxy.zap.extension.selenium.ExtensionSelenium;
import org.zaproxy.zap.extension.users.ExtensionUserManagement;
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

@SuppressWarnings("serial")
public class AuthTestDialog extends StandardFieldsDialog {

    private static final long serialVersionUID = 1L;

    private static final String CONTEXT_LABEL = "authhelper.auth.test.dialog.label.context";
    private static final String LOGIN_URL_LABEL = "authhelper.auth.test.dialog.label.loginurl";
    private static final String PASSWORD_LABEL = "authhelper.auth.test.dialog.label.password";
    private static final String USERNAME_LABEL = "authhelper.auth.test.dialog.label.username";
    private static final String BROWSER_LABEL = "authhelper.auth.test.dialog.label.browser";
    private static final String WAIT_LABEL = "authhelper.auth.test.dialog.label.wait";
    private static final String DEMO_LABEL = "authhelper.auth.test.dialog.label.demo";
    private static final String DIAGNOSTICS_LABEL = "authhelper.auth.test.dialog.label.diag";
    private static final String COPY_LABEL = "authhelper.auth.test.dialog.label.copy";

    private static final String FOUND_STR =
            Constant.messages.getString("authhelper.auth.test.dialog.results.found");

    private static final ImageIcon GREY_BALL =
            DisplayUtils.getScaledIcon(ZAP.class.getResource("/resource/icon/16/159.png"));
    private static final Icon GREEN_BALL =
            DisplayUtils.getScaledIcon(ZAP.class.getResource("/resource/icon/16/152.png"));
    private static final Icon RED_BALL =
            DisplayUtils.getScaledIcon(ZAP.class.getResource("/resource/icon/16/151.png"));
    private static final Icon YELLOW_BALL =
            DisplayUtils.getScaledIcon(ZAP.class.getResource("/resource/icon/16/154.png"));

    private JPanel resultsPanel;
    private JLabel usernameFieldLabel = new JLabel();
    private JLabel passwordFieldLabel = new JLabel();
    private JLabel statusLabel = new JLabel();
    private JLabel sessionIdLabel = new JLabel();
    private JLabel verifIdLabel = new JLabel();

    private ZapTextArea diagnosticField;
    private Boolean usernameFieldFound;
    private Boolean passwordFieldFound;

    private ExtensionAuthhelper ext;

    public AuthTestDialog(ExtensionAuthhelper ext, Frame owner) {
        super(
                owner,
                "authhelper.auth.test.dialog.title",
                DisplayUtils.getScaledDimension(600, 480),
                new String[] {
                    "authhelper.auth.test.dialog.tab.test", "authhelper.auth.test.dialog.tab.diag"
                });

        this.ext = ext;
        AuthhelperParam params = this.ext.getParam();

        this.addTargetSelectField(0, LOGIN_URL_LABEL, null, true, false);
        this.addTextField(
                0,
                CONTEXT_LABEL,
                Constant.messages.getString("authhelper.auth.test.dialog.default-context"));
        this.addTextField(0, USERNAME_LABEL, params.getUsername());
        this.addPasswordField(0, PASSWORD_LABEL, "");

        ExtensionSelenium extSel =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionSelenium.class);

        BrowsersComboBoxModel browserComboModel = extSel.createBrowsersComboBoxModel();
        browserComboModel.setSelectedBrowser(params.getBrowser());
        this.addComboField(0, BROWSER_LABEL, browserComboModel);
        this.addNumberField(0, WAIT_LABEL, 0, Integer.MAX_VALUE, params.getWait());
        this.addCheckBoxField(0, DEMO_LABEL, params.isDemoMode());
        this.addCustomComponent(0, getResultsPanel());
        this.addPadding(0);

        this.addMultilineField(1, DIAGNOSTICS_LABEL, "");
        diagnosticField = (ZapTextArea) this.getField(DIAGNOSTICS_LABEL);
        diagnosticField.setEditable(false);
        ext.setAuthDiagCollectorOutput(diagnosticField);

        JPanel buttonPanel = new JPanel();
        buttonPanel.setLayout(new GridBagLayout());
        JButton copyButton =
                new JButton(Constant.messages.getString("authhelper.auth.test.dialog.button.copy"));
        copyButton.addActionListener(
                l -> {
                    Toolkit.getDefaultToolkit()
                            .getSystemClipboard()
                            .setContents(new StringSelection(diagnosticField.getText()), null);
                });

        buttonPanel.add(new JLabel(), LayoutHelper.getGBC(0, 0, 1, 0.3D));
        buttonPanel.add(copyButton, LayoutHelper.getGBC(1, 0, 1, 0.3D));
        buttonPanel.add(new JLabel(), LayoutHelper.getGBC(2, 0, 1, 0.3D));

        this.addCustomComponent(1, COPY_LABEL, buttonPanel);

        ZapTextField text = (ZapTextField) this.getField(LOGIN_URL_LABEL);
        text.setText(params.getLoginUrl());

        this.setHideOnSave(false);
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

    private void authenticate() {
        StatsListener statsListener = null;
        try {
            this.diagnosticField.setText("");
            ext.enableAuthDiagCollector(true);

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

            // Set up browser based auth
            BrowserBasedAuthenticationMethod am =
                    ExtensionAuthhelper.BROWSER_BASED_AUTH_TYPE.createAuthenticationMethod(
                            context.getId());
            am.setLoginPageUrl(loginUrl);

            JComboBox<?> browserCombo = (JComboBox<?>) this.getField(BROWSER_LABEL);
            String browserId = ((BrowserUI) browserCombo.getSelectedItem()).getBrowser().getId();
            am.setBrowserId(browserId);
            am.setLoginPageWait(this.getIntValue(WAIT_LABEL));
            reloadAuthenticationMethod(am);
            context.setAuthenticationMethod(am);

            // Set up user
            String username = this.getStringValue(USERNAME_LABEL);
            User user = new User(context.getId(), username);
            UsernamePasswordAuthenticationCredentials upCreds =
                    new UsernamePasswordAuthenticationCredentials(
                            username, this.getStringValue(PASSWORD_LABEL));
            user.setAuthenticationCredentials(upCreds);
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
            if (this.getBoolValue(DEMO_LABEL)) {
                AuthUtils.setDemoMode(true);
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
            try {
                try {
                    AuthUtils.enableBrowserAuthentication(context, username);
                } catch (Exception e) {
                    // Must be already set, not a real problem
                }
                wd = extSel.getProxiedBrowser(browserId);
            } finally {
                AuthUtils.disableBrowserAuthentication();

                if (wd != null) {
                    wd.quit();
                }
            }
            context = session.getContext(contextName);
            ExtensionPassiveScan extPscan =
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionPassiveScan.class);

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
            if (this.getBoolValue(DEMO_LABEL)) {
                AuthUtils.setDemoMode(false);
            }
            ext.enableAuthDiagCollector(false);
        }
    }

    private void reloadAuthenticationMethod(AuthenticationMethod am) throws ConfigurationException {
        // OK, this does look weird, but it is the easiest way to actually get
        // the session management data loaded :/
        AuthenticationMethodType type = am.getType();
        Configuration config = new ZapXmlConfiguration();
        type.exportData(config, am);
        type.importData(config, am);
    }

    private void reloadSessionManagementMethod(SessionManagementMethod smm)
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
    public void save() {
        resetResultsPanel();
        Thread t = new Thread(() -> authenticate(), "ZAP-auth-tester");
        t.start();
        // Save the values for next time
        AuthhelperParam params = this.ext.getParam();
        params.setLoginUrl(this.getStringValue(LOGIN_URL_LABEL));
        params.setUsername(this.getStringValue(USERNAME_LABEL));
        JComboBox<?> browserCombo = (JComboBox<?>) this.getField(BROWSER_LABEL);
        params.setBrowser(((BrowserUI) browserCombo.getSelectedItem()).getBrowser().getId());
        params.setWait(this.getIntValue(WAIT_LABEL));
        params.setDemoMode(this.getBoolValue(DEMO_LABEL));
    }

    @Override
    public String validateFields() {
        String url = this.getStringValue(LOGIN_URL_LABEL).toLowerCase();
        if (url.isBlank()) {
            return Constant.messages.getString("authhelper.auth.test.dialog.error.nourl");
        }
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            return Constant.messages.getString("authhelper.auth.test.dialog.error.badurl");
        }
        if (this.getStringValue(CONTEXT_LABEL).isBlank()) {
            return Constant.messages.getString("authhelper.auth.test.dialog.error.nocontext");
        }
        if (this.getStringValue(USERNAME_LABEL).isBlank()) {
            return Constant.messages.getString("authhelper.auth.test.dialog.error.nouser");
        }
        if (this.getStringValue(PASSWORD_LABEL).isBlank()) {
            return Constant.messages.getString("authhelper.auth.test.dialog.error.nopassword");
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
