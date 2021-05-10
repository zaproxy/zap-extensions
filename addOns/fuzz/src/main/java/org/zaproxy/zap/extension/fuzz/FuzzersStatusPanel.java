/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2015 The ZAP Development Team
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
package org.zaproxy.zap.extension.fuzz;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.EventQueue;
import java.awt.event.KeyEvent;
import javax.swing.Action;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextPane;
import javax.swing.KeyStroke;
import javax.swing.SwingUtilities;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.view.ScanPanel2;

public class FuzzersStatusPanel extends ScanPanel2<Fuzzer<?>, FuzzersController> {

    private static final long serialVersionUID = -935993931749054827L;

    public static final String PANEL_NAME = "FuzzerScansPanel";

    private final FuzzOptions fuzzerOptions;

    private JButton startScanButton;

    private JPanel mainPanel;
    private JPanel defaultPanel;

    private FuzzerListenerImpl fuzzerListener;

    public FuzzersStatusPanel(
            FuzzOptions fuzzerOptions,
            FuzzersController mainFuzzerScanController,
            Action fuzzerUIStarter) {
        super("fuzz", FuzzerUIUtils.FUZZER_ICON, mainFuzzerScanController);

        getNewScanButton().setAction(fuzzerUIStarter);
        mainFuzzerScanController.setFuzzerScansPanel(this);

        this.fuzzerOptions = fuzzerOptions;

        setDefaultAccelerator(
                KeyStroke.getKeyStroke(
                        KeyEvent.VK_F, KeyEvent.CTRL_DOWN_MASK | KeyEvent.SHIFT_DOWN_MASK, false));
        setMnemonic(Constant.messages.getString("fuzz.panel.mnemonic").charAt(0));
    }

    @Override
    public void updateUI() {
        super.updateUI();

        SwingUtilities.updateComponentTreeUI(getDefaultPanel());
        if (getController() != null) {
            getController().updateUiFuzzResultsContentPanels();
        }
    }

    @Override
    protected Component getWorkPanel() {
        if (mainPanel == null) {
            mainPanel = new JPanel(new BorderLayout());
            mainPanel.setName("FuzzersStatusPanel");
            mainPanel.add(getDefaultPanel());
        }
        return mainPanel;
    }

    private JPanel getDefaultPanel() {
        if (defaultPanel == null) {
            JTextPane defaultMessage = new JTextPane();
            defaultMessage.setEditable(false);
            defaultMessage.setContentType("text/html");
            defaultMessage.setText(Constant.messages.getString("fuzz.fuzzer.tab.initialMessage"));

            JScrollPane scrollPane = new JScrollPane();
            scrollPane.setViewportView(defaultMessage);
            scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);

            defaultPanel = new JPanel(new BorderLayout());
            defaultPanel.add(scrollPane);
        }
        return defaultPanel;
    }

    @Override
    public void scannerStarted(Fuzzer<?> fuzzer) {
        super.scannerStarted(fuzzer);
        fuzzer.addFuzzerProgressListener(getFuzzerListener());
    }

    @Override
    protected void switchView(Fuzzer<?> fuzzer) {
        mainPanel.removeAll();
        if (fuzzer != null) {
            mainPanel.add(getController().getFuzzResultsContentPanel(fuzzer).getPanel());

        } else {
            mainPanel.add(getDefaultPanel());
        }
        mainPanel.revalidate();
        mainPanel.repaint();
    }

    @Override
    protected JButton getNewScanButton() {
        if (startScanButton == null) {
            startScanButton = new JButton();
        }
        return startScanButton;
    }

    @Override
    protected int getNumberOfScansToShow() {
        return fuzzerOptions.getMaxFinishedFuzzersInUI();
    }

    @Override
    public void clearFinishedScans() {
        if (fuzzerOptions.isPromptToClearFinishedFuzzers()) {
            JCheckBox dontPromptCheckBox =
                    new JCheckBox(
                            Constant.messages.getString("fuzz.toolbar.confirm.clear.dontPrompt"));
            Object[] messages = {
                Constant.messages.getString("fuzz.toolbar.confirm.clear"), "\n", dontPromptCheckBox
            };
            int option =
                    JOptionPane.showConfirmDialog(
                            View.getSingleton().getMainFrame(),
                            messages,
                            Constant.PROGRAM_NAME,
                            JOptionPane.YES_NO_OPTION);
            if (dontPromptCheckBox.isSelected()) {
                fuzzerOptions.setPromptToClearFinishedFuzzers(false);
            }

            if (option == JOptionPane.NO_OPTION) {
                return;
            }
        }
        super.clearFinishedScans();
    }

    private FuzzerListenerImpl getFuzzerListener() {
        if (fuzzerListener == null) {
            fuzzerListener = new FuzzerListenerImpl();
        }
        return fuzzerListener;
    }

    // Overridden to expose the method to ExtensionFuzz
    @Override
    protected void unload() {
        super.unload();
    }

    private class FuzzerListenerImpl implements FuzzerProgressListener {

        @Override
        public void fuzzerProgress(
                final int id,
                final String displayName,
                final long executedTasks,
                final long tasksToExecute) {
            EventQueue.invokeLater(
                    () -> scanProgress(id, displayName, (int) executedTasks, (int) tasksToExecute));
        }

        @Override
        public void fuzzerCompleted(final int id, final String displayName, boolean successfully) {
            EventQueue.invokeLater(() -> scanFinshed(id, displayName));
        }
    }
}
