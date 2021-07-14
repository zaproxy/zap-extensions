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
package org.zaproxy.zap.extension.authenticationhelper.statusscan.ui;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.EventQueue;
import java.awt.Toolkit;
import java.awt.event.KeyEvent;
import java.lang.reflect.InvocationTargetException;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JToolBar;
import javax.swing.KeyStroke;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.authenticationhelper.ExtensionAuthenticationHelper;
import org.zaproxy.zap.extension.authenticationhelper.statusscan.AuthenticationStatusScanListenner;
import org.zaproxy.zap.extension.authenticationhelper.statusscan.AuthenticationStatusScanner;
import org.zaproxy.zap.extension.authenticationhelper.statusscan.AuthenticationStatusTable;
import org.zaproxy.zap.extension.authenticationhelper.statusscan.AuthenticationStatusTableModel;
import org.zaproxy.zap.model.ScanController;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.ScanPanel2;

public class AuthenticationStatusPanel
        extends ScanPanel2<AuthenticationStatusScanner, ScanController<AuthenticationStatusScanner>>
        implements AuthenticationStatusScanListenner {

    private static final long serialVersionUID = 5410485722368939059L;

    private static final Logger logger = Logger.getLogger(AuthenticationStatusPanel.class);

    public static final String HTTP_MESSAGE_CONTAINER_NAME =
            "AuthenticationStatusScanMessageContainer";

    private static final String ZERO_REQUESTS_LABEL_TEXT = "0";

    private static final AuthenticationStatusTableModel EMPTY_MESSAGES_TABLE_MODEL =
            new AuthenticationStatusTableModel();

    /** The name of {@code AuthenticationStatusPanel} */
    public static final String PANEL_NAME = "AuthenticationStatusPanel";

    private ExtensionAuthenticationHelper extensionAuthenticationHelper;

    private JPanel mainPanel;

    private JButton scanButton = null;

    private AuthenticationStatusTable messagesTable;

    private JScrollPane messagesTableScrollPane;

    private JLabel successfullAuthenticationCountNameLabel;
    private JLabel successfullAuthenticationCountValueLabel;
    private JLabel failedAuthenticationCountNameLabel;
    private JLabel failedAuthenticationCountValueLabel;
    private JLabel conflictAuthenticationCountNameLabel;
    private JLabel conflictAuthenticationCountValueLabel;
    private JLabel unknownAuthenticationCountNameLabel;
    private JLabel unknownAuthenticationCountValueLabel;

    @SuppressWarnings("deprecation")
    public AuthenticationStatusPanel(ExtensionAuthenticationHelper extensionAuthenticationHelper) {
        super(
                "authenticationhelper",
                new ImageIcon(
                        ExtensionAuthenticationHelper.class.getResource(
                                "/org/zaproxy/zap/extension/authenticationhelper/resources/help/contents/images/key.png")),
                extensionAuthenticationHelper);
        this.extensionAuthenticationHelper = extensionAuthenticationHelper;

        // TODO Remove warn suppression and use View.getMenuShortcutKeyStroke with newer
        // ZAP (or use getMenuShortcutKeyMaskEx() with Java 10+)
        setDefaultAccelerator(
                KeyStroke.getKeyStroke(
                        KeyEvent.VK_Z,
                        Toolkit.getDefaultToolkit().getMenuShortcutKeyMask()
                                | KeyEvent.SHIFT_DOWN_MASK,
                        false));
        setMnemonic(Constant.messages.getChar("authenticationhelper.panel.mnemonic"));
    }

    @Override
    protected Component getWorkPanel() {
        if (mainPanel == null) {
            mainPanel = new JPanel(new BorderLayout());
            mainPanel.add(getMessagesTableScrollPane());
        }
        return mainPanel;
    }

    private JScrollPane getMessagesTableScrollPane() {
        if (messagesTableScrollPane == null) {
            messagesTableScrollPane = new JScrollPane();
            messagesTableScrollPane.setName("AuthenticationStatusMessagesPane");
            messagesTableScrollPane.setViewportView(getMessagesTable());
        }
        return messagesTableScrollPane;
    }

    private AuthenticationStatusTable getMessagesTable() {
        if (messagesTable == null) {
            messagesTable = new AuthenticationStatusTable(EMPTY_MESSAGES_TABLE_MODEL);
            messagesTable.setName(HTTP_MESSAGE_CONTAINER_NAME);
        }
        return messagesTable;
    }

    private JLabel getSuccessfulAuthenticationCountNameLabel() {
        if (successfullAuthenticationCountNameLabel == null) {
            successfullAuthenticationCountNameLabel = new JLabel();
            successfullAuthenticationCountNameLabel.setText(
                    Constant.messages.getString(
                            "authenticationhelper.toolbar.successsfulAuthenticationCount.label"));
        }
        return successfullAuthenticationCountNameLabel;
    }

    private JLabel getSuccessfulAuthenticationCountValueLabel() {
        if (successfullAuthenticationCountValueLabel == null) {
            successfullAuthenticationCountValueLabel = new JLabel();
            successfullAuthenticationCountValueLabel.setText(ZERO_REQUESTS_LABEL_TEXT);
        }
        return successfullAuthenticationCountValueLabel;
    }

    private JLabel getFailedAuthenticationCountNameLabel() {
        if (failedAuthenticationCountNameLabel == null) {
            failedAuthenticationCountNameLabel = new JLabel();
            failedAuthenticationCountNameLabel.setText(
                    Constant.messages.getString(
                            "authenticationhelper.toolbar.failedAuthenticationCount.label"));
        }
        return failedAuthenticationCountNameLabel;
    }

    private JLabel getFailedAuthenticationCountValueLabel() {
        if (failedAuthenticationCountValueLabel == null) {
            failedAuthenticationCountValueLabel = new JLabel();
            failedAuthenticationCountValueLabel.setText(ZERO_REQUESTS_LABEL_TEXT);
        }
        return failedAuthenticationCountValueLabel;
    }

    private JLabel getConflictingAuthenticationCountNameLabel() {
        if (conflictAuthenticationCountNameLabel == null) {
            conflictAuthenticationCountNameLabel = new JLabel();
            conflictAuthenticationCountNameLabel.setText(
                    Constant.messages.getString(
                            "authenticationhelper.toolbar.conflictingAuthenticationCount.label"));
        }
        return conflictAuthenticationCountNameLabel;
    }

    private JLabel getConflictingAuthenticationCountValueLabel() {
        if (conflictAuthenticationCountValueLabel == null) {
            conflictAuthenticationCountValueLabel = new JLabel();
            conflictAuthenticationCountValueLabel.setText(ZERO_REQUESTS_LABEL_TEXT);
        }
        return conflictAuthenticationCountValueLabel;
    }

    private JLabel getUnknownAuthenticationCountNameLabel() {
        if (unknownAuthenticationCountNameLabel == null) {
            unknownAuthenticationCountNameLabel = new JLabel();
            unknownAuthenticationCountNameLabel.setText(
                    Constant.messages.getString(
                            "authenticationhelper.toolbar.unknownAuthenticationCount.label"));
        }
        return unknownAuthenticationCountNameLabel;
    }

    private JLabel getUnknownAuthenticationCountValueLabel() {
        if (unknownAuthenticationCountValueLabel == null) {
            unknownAuthenticationCountValueLabel = new JLabel();
            unknownAuthenticationCountValueLabel.setText(ZERO_REQUESTS_LABEL_TEXT);
        }
        return unknownAuthenticationCountValueLabel;
    }

    @Override
    protected int addToolBarElements(JToolBar toolbar, Location loc, int x) {
        if (Location.afterProgressBar.equals(loc)) {
            toolbar.add(new JToolBar.Separator(), getGBC(x++, 0));
            toolbar.add(getSuccessfulAuthenticationCountNameLabel(), getGBC(x++, 0));
            toolbar.add(getSuccessfulAuthenticationCountValueLabel(), getGBC(x++, 0));

            toolbar.add(new JToolBar.Separator(), getGBC(x++, 0));
            toolbar.add(getFailedAuthenticationCountNameLabel(), getGBC(x++, 0));
            toolbar.add(getFailedAuthenticationCountValueLabel(), getGBC(x++, 0));

            toolbar.add(new JToolBar.Separator(), getGBC(x++, 0));
            toolbar.add(getConflictingAuthenticationCountNameLabel(), getGBC(x++, 0));
            toolbar.add(getConflictingAuthenticationCountValueLabel(), getGBC(x++, 0));

            toolbar.add(new JToolBar.Separator(), getGBC(x++, 0));
            toolbar.add(getUnknownAuthenticationCountNameLabel(), getGBC(x++, 0));
            toolbar.add(getUnknownAuthenticationCountValueLabel(), getGBC(x++, 0));
        }
        return x;
    }

    private void updateSuccessfulAuthenticationCount(int count) {
        if (getSelectedScanner() != null) {
            this.getSuccessfulAuthenticationCountValueLabel().setText(Integer.toString(count));
        } else {
            updateZeroSuccessfulAuthenticationCount();
        }
    }

    private void updateZeroSuccessfulAuthenticationCount() {
        getSuccessfulAuthenticationCountValueLabel().setText(ZERO_REQUESTS_LABEL_TEXT);
    }

    private void updateZeroFailedAuthenticationCount() {
        getFailedAuthenticationCountValueLabel().setText(ZERO_REQUESTS_LABEL_TEXT);
    }

    private void updateZeroConflictingAuthenticationCount() {
        getConflictingAuthenticationCountValueLabel().setText(ZERO_REQUESTS_LABEL_TEXT);
    }

    private void updateZeroUnknownAuthenticationCount() {
        getUnknownAuthenticationCountValueLabel().setText(ZERO_REQUESTS_LABEL_TEXT);
    }

    private void updateFailedAuthenticationCount(int count) {
        if (getSelectedScanner() != null) {
            this.getFailedAuthenticationCountValueLabel().setText(Integer.toString(count));
        } else {
            updateZeroFailedAuthenticationCount();
        }
    }

    private void updateConflictingAuthenticationCount(int count) {
        if (getSelectedScanner() != null) {
            this.getConflictingAuthenticationCountValueLabel().setText(Integer.toString(count));
        } else {
            updateZeroConflictingAuthenticationCount();
        }
    }

    private void updateUnknownAuthenticationCount(int count) {
        if (getSelectedScanner() != null) {
            this.getUnknownAuthenticationCountValueLabel().setText(Integer.toString(count));
        } else {
            updateZeroUnknownAuthenticationCount();
        }
    }

    @Override
    public void switchView(final AuthenticationStatusScanner scanner) {
        if (View.isInitialised() && !EventQueue.isDispatchThread()) {
            try {
                EventQueue.invokeAndWait(() -> switchView(scanner));
            } catch (InvocationTargetException | InterruptedException e) {
                logger.error("Failed to switch view: " + e.getMessage(), e);
            }
            return;
        }
        if (scanner != null) {
            getMessagesTable().setModel(scanner.getAuthenticationStatusTableModel());
        } else {
            getMessagesTable().setModel(EMPTY_MESSAGES_TABLE_MODEL);
        }

        updateAuthenticationCounts(scanner);
    }

    private void updateAuthenticationCounts(AuthenticationStatusScanner scanner) {
        if (scanner != null) {
            updateSuccessfulAuthenticationCount(scanner.getSuccessfulAuthenticationCount());
            updateFailedAuthenticationCount(scanner.getFailedAuthenticationCount());
            updateConflictingAuthenticationCount(scanner.getConflictingAuthenticationCount());
            updateUnknownAuthenticationCount(scanner.getConflictingAuthenticationCount());
        } else {
            updateZeroSuccessfulAuthenticationCount();
            updateZeroFailedAuthenticationCount();
            updateZeroConflictingAuthenticationCount();
            updateZeroUnknownAuthenticationCount();
        }
    }

    @Override
    public JButton getNewScanButton() {
        if (scanButton == null) {
            scanButton =
                    new JButton(
                            Constant.messages.getString(
                                    "authenticationhelper.toolbar.button.check"));
            scanButton.setIcon(
                    DisplayUtils.getScaledIcon(
                            new ImageIcon(
                                    AuthenticationStatusPanel.class.getResource(
                                            "/org/zaproxy/zap/extension/authenticationhelper/resources/help/contents/images/key.png"))));
            scanButton.addActionListener(
                    e ->
                            extensionAuthenticationHelper.showCheckAuthenticationDialog(
                                    getSiteTreeTarget()));
        }
        return scanButton;
    }

    private SiteNode getSiteTreeTarget() {
        if (!extensionAuthenticationHelper
                .getView()
                .getSiteTreePanel()
                .getTreeSite()
                .isSelectionEmpty()) {
            return (SiteNode)
                    extensionAuthenticationHelper
                            .getView()
                            .getSiteTreePanel()
                            .getTreeSite()
                            .getSelectionPath()
                            .getLastPathComponent();
        }
        return null;
    }

    @Override
    protected int getNumberOfScansToShow() {
        return 5;
    }

    @Override
    public void updateProgress(
            int id,
            String host,
            int progress,
            int successCount,
            int failedCount,
            int conflictingCount,
            int unknownCount) {

        updateSuccessfulAuthenticationCount(successCount);
        updateFailedAuthenticationCount(failedCount);
        updateConflictingAuthenticationCount(conflictingCount);
        updateUnknownAuthenticationCount(unknownCount);
        super.scanProgress(id, host, progress, 100);
    }

    @Override
    public void scanCompleted(int id, String host) {
        super.scanFinshed(id, host);
    }
}
