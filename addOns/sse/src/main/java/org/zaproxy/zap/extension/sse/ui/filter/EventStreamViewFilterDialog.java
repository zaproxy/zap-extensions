/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2013 The ZAP Development Team
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
package org.zaproxy.zap.extension.sse.ui.filter;

import java.awt.Dimension;
import java.awt.Frame;
import java.awt.GridBagLayout;
import java.awt.HeadlessException;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import javax.swing.AbstractAction;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.KeyStroke;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.AbstractDialog;
import org.zaproxy.zap.extension.sse.ui.EventStreamUiHelper;

/** Filter Server-Sent Events in EventStream-Panel. Show only specific ones. */
@SuppressWarnings("serial")
public class EventStreamViewFilterDialog extends AbstractDialog {
    private static final long serialVersionUID = 4750602961870366348L;

    /** Description of the dialog. */
    private static final String MSG = Constant.messages.getString("sse.filter.label.desc");

    /** The dialogs panel. */
    private JPanel dialogPanel = null;

    /** The actions area with apply, cancel and reset button. */
    private JPanel actionsPanel = null;

    private JButton btnApply = null;
    private JButton btnCancel = null;
    private JButton btnReset = null;

    private int exitResult = JOptionPane.CANCEL_OPTION;

    /** The model holding the values set by this filter dialog. */
    private EventStreamViewFilter filter = new EventStreamViewFilter();

    private EventStreamUiHelper sseUiHelper;

    /**
     * @param owner
     * @param isModal
     * @throws HeadlessException
     */
    public EventStreamViewFilterDialog(Frame owner, boolean isModal) throws HeadlessException {
        super(owner, isModal);
        sseUiHelper = new EventStreamUiHelper();
        initialize();
    }

    /** This method initializes this */
    private void initialize() {
        setContentPane(getJPanel());
        setVisible(false);
        setTitle(Constant.messages.getString("sse.filter.title"));

        getRootPane().setDefaultButton(btnApply);

        //  Handle escape key to close the dialog
        KeyStroke escape = KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0, false);
        AbstractAction escapeAction =
                new AbstractAction() {
                    private static final long serialVersionUID = 1L;

                    @Override
                    public void actionPerformed(ActionEvent e) {
                        EventStreamViewFilterDialog.this.dispose();
                    }
                };

        getRootPane().getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(escape, "ESCAPE");
        getRootPane().getActionMap().put("ESCAPE", escapeAction);
        pack();
    }

    /**
     * This method initializes the dialog's {@link JPanel}.
     *
     * @return javax.swing.JPanel
     */
    private JPanel getJPanel() {
        if (dialogPanel == null) {
            dialogPanel = new JPanel();
            dialogPanel.setLayout(new GridBagLayout());
            dialogPanel.setPreferredSize(new Dimension(sseUiHelper.getDialogWidth() + 20, 280));

            int y = 0;

            JLabel description = new JLabel(MSG);
            description.setPreferredSize(new Dimension(sseUiHelper.getDialogWidth() - 20, 60));
            description.setMaximumSize(new Dimension(sseUiHelper.getDialogWidth() - 20, 100));
            dialogPanel.add(description, sseUiHelper.getDescriptionConstraints(0, y++));

            // add submit panel
            dialogPanel.add(getActionsPanel(), sseUiHelper.getFieldConstraints(1, y));
        }

        return dialogPanel;
    }

    /**
     * This method initializes the submit container containing all buttons.
     *
     * @return javax.swing.JPanel
     */
    private JPanel getActionsPanel() {
        if (actionsPanel == null) {
            actionsPanel = new JPanel();
            actionsPanel.add(getBtnCancel());
            actionsPanel.add(getBtnReset());
            actionsPanel.add(getBtnApply());
        }
        return actionsPanel;
    }

    /**
     * This method initializes btnApply
     *
     * @return javax.swing.JButton
     */
    private JButton getBtnApply() {
        if (btnApply == null) {
            btnApply = new JButton();
            btnApply.setText(Constant.messages.getString("history.filter.button.apply"));
            btnApply.addActionListener(
                    e -> {
                        exitResult = JOptionPane.OK_OPTION;
                        EventStreamViewFilterDialog.this.dispose();
                    });
        }
        return btnApply;
    }
    /**
     * This method initializes btnCancel
     *
     * @return javax.swing.JButton
     */
    private JButton getBtnCancel() {
        if (btnCancel == null) {
            btnCancel = new JButton();
            btnCancel.setText(Constant.messages.getString("all.button.cancel"));
            btnCancel.addActionListener(
                    e -> {
                        exitResult = JOptionPane.CANCEL_OPTION;
                        EventStreamViewFilterDialog.this.dispose();
                    });
        }
        return btnCancel;
    }

    public int showDialog() {
        setVisible(true);
        return exitResult;
    }

    /**
     * This method initializes btnReset
     *
     * @return reset button
     */
    private JButton getBtnReset() {
        if (btnReset == null) {
            btnReset = new JButton();
            btnReset.setText(Constant.messages.getString("history.filter.button.clear"));
            btnReset.addActionListener(
                    e -> {
                        exitResult = JOptionPane.NO_OPTION;
                        filter.reset();
                    });
        }
        return btnReset;
    }

    /** @return model holding the values set by this dialog */
    public EventStreamViewFilter getFilter() {
        return filter;
    }
}
