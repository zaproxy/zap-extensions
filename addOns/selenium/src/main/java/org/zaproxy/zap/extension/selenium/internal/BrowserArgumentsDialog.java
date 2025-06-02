/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.zap.extension.selenium.internal;

import java.awt.BorderLayout;
import java.awt.Dialog;
import java.awt.Dialog.ModalityType;
import java.awt.Dimension;
import java.awt.Rectangle;
import java.awt.Toolkit;
import java.awt.Window;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.swing.AbstractAction;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.KeyStroke;
import javax.swing.SortOrder;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.help.ExtensionHelp;
import org.zaproxy.zap.view.AbstractMultipleOptionsBaseTablePanel;

@SuppressWarnings("serial")
public class BrowserArgumentsDialog extends JDialog {

    private static final long serialVersionUID = 1L;

    private final BrowserArgumentsOptionsPanel optionsPanel;
    private final AtomicBoolean confirmRemoveBrowserArgument;

    private boolean firstTime;

    public BrowserArgumentsDialog(
            Dialog owner,
            BrowserArgumentsTableModel model,
            AtomicBoolean confirmRemoveBrowserArgument) {
        super(
                owner,
                Constant.messages.getString("selenium.options.browser.arguments.title"),
                ModalityType.DOCUMENT_MODAL);

        firstTime = true;
        optionsPanel = new BrowserArgumentsOptionsPanel(owner, model);
        this.confirmRemoveBrowserArgument = confirmRemoveBrowserArgument;

        JPanel buttonsPanel = new JPanel();
        buttonsPanel.setLayout(new BoxLayout(buttonsPanel, BoxLayout.LINE_AXIS));
        buttonsPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

        JButton helpButton = new JButton();
        helpButton.setIcon(ExtensionHelp.getHelpIcon());
        helpButton.setToolTipText(Constant.messages.getString("help.dialog.button.tooltip"));

        helpButton.addActionListener(e -> ExtensionHelp.showHelp("addon.selenium.options"));
        buttonsPanel.add(helpButton);
        buttonsPanel.add(Box.createHorizontalGlue());
        buttonsPanel.add(Box.createRigidArea(new Dimension(5, 0)));

        JButton closeButton =
                new JButton(
                        Constant.messages.getString(
                                "selenium.options.browser.arguments.close.button"));
        closeButton.addActionListener(e -> dispose());
        buttonsPanel.add(closeButton);

        JPanel panel = new JPanel(new BorderLayout());
        panel.add(optionsPanel, BorderLayout.CENTER);
        panel.add(buttonsPanel, BorderLayout.PAGE_END);

        setContentPane(panel);
        pack();

        KeyStroke escape = KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0, false);
        AbstractAction escapeAction =
                new AbstractAction() {

                    private static final long serialVersionUID = 1L;

                    @Override
                    public void actionPerformed(ActionEvent e) {
                        dispose();
                    }
                };
        getRootPane().getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(escape, "ESCAPE");
        getRootPane().getActionMap().put("ESCAPE", escapeAction);
    }

    @Override
    public void setVisible(boolean b) {
        if (firstTime) {
            centreOnOwner();
            firstTime = false;
        }

        optionsPanel.setRemoveWithoutConfirmation(!confirmRemoveBrowserArgument.get());
        super.setVisible(b);
    }

    @Override
    public void dispose() {
        confirmRemoveBrowserArgument.set(!optionsPanel.isRemoveWithoutConfirmation());

        super.dispose();
    }

    private void centreOnOwner() {
        Dimension frameSize = getSize();
        Rectangle mainrect = getMainRectangle();
        int x = mainrect.x + (mainrect.width - frameSize.width) / 2;
        int y = mainrect.y + (mainrect.height - frameSize.height) / 2;
        setLocation(x, y);
    }

    private Rectangle getMainRectangle() {
        Window owner = getOwner();
        if (owner != null) {
            return owner.getBounds();
        }
        return new Rectangle(Toolkit.getDefaultToolkit().getScreenSize());
    }

    private static class BrowserArgumentsOptionsPanel
            extends AbstractMultipleOptionsBaseTablePanel<BrowserArgument> {

        private static final long serialVersionUID = 1L;

        private final Dialog parent;
        private DialogAddBrowserArgument addDialog;
        private DialogModifyBrowserArgument modifyDialog;

        public BrowserArgumentsOptionsPanel(Dialog parent, BrowserArgumentsTableModel model) {
            super(model);

            this.parent = parent;

            getTable().getColumnExt(0).setPreferredWidth(150);
            getTable().getColumnExt(1).setPreferredWidth(200);
            getTable().setSortOrder(1, SortOrder.ASCENDING);
            getTable().setVisibleRowCount(10);
        }

        @Override
        public BrowserArgument showAddDialogue() {
            if (addDialog == null) {
                addDialog = new DialogAddBrowserArgument(parent);
                addDialog.pack();
            }
            addDialog.setBrowserArguments(model.getElements());
            addDialog.setVisible(true);

            BrowserArgument argument = addDialog.getElem();
            addDialog.clear();
            return argument;
        }

        @Override
        public BrowserArgument showModifyDialogue(BrowserArgument e) {
            if (modifyDialog == null) {
                modifyDialog = new DialogModifyBrowserArgument(parent);
                modifyDialog.pack();
            }
            modifyDialog.setBrowserArguments(model.getElements());
            modifyDialog.setElem(e);
            modifyDialog.setVisible(true);

            BrowserArgument argument = modifyDialog.getElem();
            modifyDialog.clear();

            if (!argument.equals(e)) {
                return argument;
            }

            return null;
        }

        @Override
        public boolean showRemoveDialogue(BrowserArgument e) {
            JCheckBox removeWithoutConfirmationCheckBox =
                    new JCheckBox(
                            Constant.messages.getString(
                                    "selenium.options.dialog.remove.label.checkbox"));
            Object[] messages = {
                Constant.messages.getString("selenium.options.browser.arguments.remove.text"),
                " ",
                removeWithoutConfirmationCheckBox
            };
            int option =
                    JOptionPane.showOptionDialog(
                            parent,
                            messages,
                            Constant.messages.getString(
                                    "selenium.options.browser.arguments.remove.title"),
                            JOptionPane.OK_CANCEL_OPTION,
                            JOptionPane.QUESTION_MESSAGE,
                            null,
                            new String[] {
                                Constant.messages.getString(
                                        "selenium.options.dialog.remove.button.remove"),
                                Constant.messages.getString(
                                        "selenium.options.dialog.remove.button.cancel")
                            },
                            null);

            if (option == JOptionPane.OK_OPTION) {
                setRemoveWithoutConfirmation(removeWithoutConfirmationCheckBox.isSelected());

                return true;
            }

            return false;
        }
    }
}
