/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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
package org.zaproxy.zap.extension.authenticationhelper;

import java.awt.Dimension;
import java.awt.EventQueue;
import java.awt.event.KeyEvent;
import java.net.MalformedURLException;
import java.net.URL;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.List;
import javax.swing.Icon;
import javax.swing.ImageIcon;
import javax.swing.KeyStroke;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control.Mode;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.ExtensionHookMenu;
import org.parosproxy.paros.extension.ExtensionHookView;
import org.parosproxy.paros.extension.SessionChangedListener;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.authenticationhelper.statusscan.AuthenticationStatusScanController;
import org.zaproxy.zap.extension.authenticationhelper.statusscan.AuthenticationStatusScanner;
import org.zaproxy.zap.extension.authenticationhelper.statusscan.ui.AuthenticationHelperDialog;
import org.zaproxy.zap.extension.authenticationhelper.statusscan.ui.AuthenticationHelperOptionsPanel;
import org.zaproxy.zap.extension.authenticationhelper.statusscan.ui.AuthenticationStatusPanel;
import org.zaproxy.zap.extension.authenticationhelper.statusscan.ui.PopupMenuItemCheckAuthentication;
import org.zaproxy.zap.extension.help.ExtensionHelp;
import org.zaproxy.zap.model.ScanController;
import org.zaproxy.zap.model.Target;
import org.zaproxy.zap.users.User;
import org.zaproxy.zap.view.ZapMenuItem;

/**
 * An extension for
 *
 * <ul>
 *   <li>automated authentication configuration
 *   <li>guided authentication configuration
 *   <li>authentication status scanning
 * </ul>
 */
public class ExtensionAuthenticationHelper extends ExtensionAdaptor
        implements SessionChangedListener, ScanController<AuthenticationStatusScanner> {

    private static final Logger logger = Logger.getLogger(ExtensionAuthenticationHelper.class);

    /** Name of the extension {@code ExtensionAuthenticationHelper}. */
    public static final String NAME = "ExtensionAuthenticationHelper";

    public static final int EXTENSION_ORDER = 19;

    private Icon authenticationIcon;

    private ZapMenuItem toolMenuItemCheckAuthentication;
    private PopupMenuItemCheckAuthentication popupMenuItemCheckAuthentication;

    private OptionsParamAuthenticationHelper config;

    private AuthenticationHelperDialog authenticationHelperDialog = null;
    private AuthenticationStatusPanel authenticationStatusPanel;

    private AuthenticationStatusScanController scanController;

    private AuthenticationHelperOptionsPanel authenticationHelperOptionsPanel;

    public ExtensionAuthenticationHelper() {
        super(NAME);
        setOrder(EXTENSION_ORDER);
    }

    @Override
    public void init() {
        super.init();

        scanController = new AuthenticationStatusScanController(this);
        config = new OptionsParamAuthenticationHelper();
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        extensionHook.addSessionListener(this);
        extensionHook.addOptionsParamSet(config);

        if (getView() != null) {
            ExtensionHookView hookView = extensionHook.getHookView();
            ExtensionHookMenu hookMenu = extensionHook.getHookMenu();

            hookMenu.addToolsMenuItem(getMenuItemCheckAuthentication());
            hookMenu.addPopupMenuItem(getPopupMenuItemCheckAuthentication());

            hookView.addOptionPanel(getOptionsAuthenticationHelperPanel());
            hookView.addStatusPanel(getAuthenticationStatusPanel());

            ExtensionHelp.enableHelpKey(getAuthenticationStatusPanel(), "authenticationhelper.tab");
        }
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString("authenticationhelper.name");
    }

    @Override
    public void unload() {
        super.unload();

        if (getView() != null) {
            if (authenticationHelperDialog != null) {
                authenticationHelperDialog.dispose();
            }

            if (scanController != null) {
                scanController.stopAllScans();
            }
            getView().getSessionDialog().removeParamPanel(authenticationHelperOptionsPanel);
        }
    }

    public void showCheckAuthenticationDialog(SiteNode node) {
        showCheckAuthenticationDialog(node != null ? new Target(node) : null);
    }

    public void showCheckAuthenticationDialog(Target target) {
        if (authenticationHelperDialog == null) {
            authenticationHelperDialog =
                    new AuthenticationHelperDialog(
                            this, View.getSingleton().getMainFrame(), new Dimension(660, 480));
        }
        if (authenticationHelperDialog.isVisible()) {
            authenticationHelperDialog.toFront();
            return;
        }

        authenticationHelperDialog.init(target);
        authenticationHelperDialog.setVisible(true);
    }

    private AuthenticationStatusPanel getAuthenticationStatusPanel() {
        if (authenticationStatusPanel == null) {
            authenticationStatusPanel = new AuthenticationStatusPanel(this);
        }
        return authenticationStatusPanel;
    }

    private AuthenticationHelperOptionsPanel getOptionsAuthenticationHelperPanel() {
        if (authenticationHelperOptionsPanel == null) {
            authenticationHelperOptionsPanel = new AuthenticationHelperOptionsPanel(config);
        }
        return authenticationHelperOptionsPanel;
    }

    private ZapMenuItem getMenuItemCheckAuthentication() {
        if (toolMenuItemCheckAuthentication == null) {
            toolMenuItemCheckAuthentication =
                    new ZapMenuItem(
                            "authenticationhelper.topmenu.tools.title",
                            KeyStroke.getKeyStroke(KeyEvent.VK_F3, 0));

            toolMenuItemCheckAuthentication.addActionListener(
                    e -> {
                        showCheckAuthenticationDialog((Target) null);
                    });
        }
        return toolMenuItemCheckAuthentication;
    }

    private PopupMenuItemCheckAuthentication getPopupMenuItemCheckAuthentication() {
        if (popupMenuItemCheckAuthentication == null) {
            popupMenuItemCheckAuthentication = new PopupMenuItemCheckAuthentication(this);
            popupMenuItemCheckAuthentication.setMenuIndex(3);
        }
        return popupMenuItemCheckAuthentication;
    }

    public Icon getIcon() {
        if (authenticationIcon == null) {
            authenticationIcon =
                    new ImageIcon(
                            ExtensionAuthenticationHelper.class.getResource(
                                    "authenticationhelper/key.png"));
        }
        return authenticationIcon;
    }

    @Override
    public String getAuthor() {
        return Constant.ZAP_TEAM;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("authenticationhelper.desc");
    }

    @Override
    public URL getURL() {
        try {
            return new URL(Constant.ZAP_EXTENSIONS_PAGE);
        } catch (MalformedURLException e) {
            return null;
        }
    }

    @Override
    public void sessionAboutToChange(Session session) {
        this.scanController.reset();
        if (View.isInitialised()) {
            this.getAuthenticationStatusPanel().reset();
            if (authenticationHelperDialog != null) {
                authenticationHelperDialog.reset();
            }
        }
    }

    @Override
    public void sessionChanged(Session session) {
        if (EventQueue.isDispatchThread()) {
            sessionChangedEventHandler(session);
        } else {
            try {
                EventQueue.invokeAndWait(() -> sessionChangedEventHandler(session));
            } catch (Exception e) {
                logger.error(e.getMessage(), e);
            }
        }
    }

    private void sessionChangedEventHandler(Session session) {
        // Clear all scans
        if (View.isInitialised()) {
            getAuthenticationStatusPanel().reset();
        }
    }

    @Override
    public List<String> getActiveActions() {
        List<AuthenticationStatusScanner> activeAuthenticationStatusScans =
                scanController.getActiveScans();
        if (activeAuthenticationStatusScans.isEmpty()) {
            return null;
        }

        String authenticationStatusActionPrefix =
                Constant.messages.getString("authenticationhelper.activeActionPrefix");
        List<String> activeActions = new ArrayList<>(activeAuthenticationStatusScans.size());
        for (AuthenticationStatusScanner activeAuthenticationStatusScan :
                activeAuthenticationStatusScans) {
            activeActions.add(
                    MessageFormat.format(
                            authenticationStatusActionPrefix,
                            activeAuthenticationStatusScan.getDisplayName()));
        }
        return activeActions;
    }

    public int startScan(Target target, User user, Object[] customConfigurations) {
        return startScan(
                createDisplayName(target, customConfigurations),
                target,
                user,
                customConfigurations);
    }

    private String createDisplayName(Target target, Object[] customConfigurations) {
        return Constant.messages.getString("context.prefixName", target.getContext().getName());
    }

    @Override
    public int startScan(
            String displayName, Target target, User user, Object[] customConfigurations) {
        int id = scanController.startScan(displayName, target, user, customConfigurations);

        if (View.isInitialised()) {
            addScantoUi(scanController.getScan(id));
        }
        return id;
    }

    private void addScantoUi(final AuthenticationStatusScanner scan) {
        if (!EventQueue.isDispatchThread()) {
            EventQueue.invokeLater(() -> addScantoUi(scan));
            return;
        }

        getAuthenticationStatusPanel().scannerStarted(scan);
        scan.setScanListener(getAuthenticationStatusPanel());
        getAuthenticationStatusPanel().switchView(scan);
        getAuthenticationStatusPanel().setTabFocus();
    }

    @Override
    public List<AuthenticationStatusScanner> getAllScans() {
        return scanController.getAllScans();
    }

    @Override
    public List<AuthenticationStatusScanner> getActiveScans() {
        return scanController.getActiveScans();
    }

    @Override
    public AuthenticationStatusScanner getScan(int id) {
        return this.scanController.getScan(id);
    }

    @Override
    public void stopScan(int id) {
        this.scanController.stopScan(id);
    }

    @Override
    public void stopAllScans() {
        this.scanController.stopAllScans();
    }

    @Override
    public void pauseScan(int id) {
        this.scanController.pauseScan(id);
        if (View.isInitialised()) {
            // Update the UI in case this was initiated from the API
            this.getAuthenticationStatusPanel().updateScannerUI();
        }
    }

    @Override
    public void pauseAllScans() {
        this.scanController.pauseAllScans();
        if (View.isInitialised()) {
            // Update the UI in case this was initiated from the API
            this.getAuthenticationStatusPanel().updateScannerUI();
        }
    }

    @Override
    public void resumeScan(int id) {
        this.scanController.resumeScan(id);
        if (View.isInitialised()) {
            // Update the UI in case this was initiated from the API
            this.getAuthenticationStatusPanel().updateScannerUI();
        }
    }

    @Override
    public void resumeAllScans() {
        this.scanController.resumeAllScans();
        if (View.isInitialised()) {
            // Update the UI in case this was initiated from the API
            this.getAuthenticationStatusPanel().updateScannerUI();
        }
    }

    @Override
    public AuthenticationStatusScanner removeScan(int id) {
        return scanController.removeScan(id);
    }

    @Override
    public int removeAllScans() {
        return scanController.removeAllScans();
    }

    @Override
    public int removeFinishedScans() {
        return scanController.removeFinishedScans();
    }

    @Deprecated
    @Override
    public AuthenticationStatusScanner getLastScan() {
        return null;
    }

    @Override
    public void sessionScopeChanged(Session session) {}

    @Override
    public void sessionModeChanged(Mode mode) {
        // ignore
    }

    @Override
    public void destroy() {
        stopAllScans();
        if (View.isInitialised()) {
            this.getAuthenticationStatusPanel().reset();
        }
    }

    public OptionsParamAuthenticationHelper getOptionsParam() {
        return config;
    }
}
