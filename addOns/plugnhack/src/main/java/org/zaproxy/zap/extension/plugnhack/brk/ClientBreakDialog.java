/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
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
package org.zaproxy.zap.extension.plugnhack.brk;

import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.HeadlessException;
import java.awt.Insets;
import java.awt.event.ActionListener;
import java.util.regex.PatternSyntaxException;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextField;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.AbstractDialog;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.plugnhack.ExtensionPlugNHack;
import org.zaproxy.zap.extension.plugnhack.MonitoredPagesManager;
import org.zaproxy.zap.view.LayoutHelper;

@SuppressWarnings("serial")
public abstract class ClientBreakDialog extends AbstractDialog {

    private static final long serialVersionUID = 1L;

    private ExtensionPlugNHack extension;
    protected ClientBreakpointsUiManagerInterface breakPointsManager;

    private JPanel jPanel = null;
    private JButton btnSubmit = null;
    private JButton btnCancel = null;
    private JScrollPane jScrollPane = null;

    private JComboBox<String> typesCombo = null;
    private JComboBox<String> clientsCombo = null;
    private JTextField payloadPattern = null;

    public ClientBreakDialog(
            ExtensionPlugNHack extension, ClientBreakpointsUiManagerInterface breakPointsManager)
            throws HeadlessException {
        super(View.getSingleton().getMainFrame(), true);
        setDefaultCloseOperation(DISPOSE_ON_CLOSE);
        this.extension = extension;
        this.breakPointsManager = breakPointsManager;

        initialize();
    }

    private void initialize() {
        setTitle(getDialogTitle());
        setContentPane(getJPanel());

        addWindowListener(
                new java.awt.event.WindowAdapter() {
                    @Override
                    public void windowOpened(java.awt.event.WindowEvent e) {}

                    @Override
                    public void windowClosing(java.awt.event.WindowEvent e) {
                        btnCancel.doClick();
                    }
                });

        pack();
    }

    protected abstract String getDialogTitle();

    protected abstract ActionListener getActionListenerSubmit();

    protected abstract ActionListener getActionListenerCancel();

    protected abstract String getBtnSubmitText();

    private JPanel getJPanel() {
        if (jPanel == null) {
            jPanel = new JPanel();
            jPanel.setLayout(new GridBagLayout());

            Dimension size = new Dimension(500, 150);
            jPanel.setPreferredSize(size);
            jPanel.setMinimumSize(size);

            GridBagConstraints constraints = new GridBagConstraints();
            constraints.anchor = java.awt.GridBagConstraints.NORTHWEST;
            constraints.fill = java.awt.GridBagConstraints.HORIZONTAL;
            constraints.gridwidth = 3;
            constraints.gridy = 2;
            constraints.ipady = 10;
            constraints.weightx = 1.0;
            constraints.insets = new Insets(2, 10, 5, 10);
            jPanel.add(getJScrollPane(), constraints);

            constraints = new GridBagConstraints();
            constraints.fill = java.awt.GridBagConstraints.HORIZONTAL;
            constraints.insets = new java.awt.Insets(2, 10, 2, 5);
            constraints.gridy = 5;
            constraints.weightx = 1.0D;
            jPanel.add(new JLabel(), constraints);

            constraints = new GridBagConstraints();
            constraints.anchor = java.awt.GridBagConstraints.EAST;
            constraints.insets = new java.awt.Insets(2, 2, 2, 2);
            constraints.gridx = 1;
            constraints.gridy = 5;
            jPanel.add(getBtnCancel(), constraints);

            constraints = new GridBagConstraints();
            constraints.anchor = java.awt.GridBagConstraints.EAST;
            constraints.insets = new java.awt.Insets(2, 2, 2, 10);
            constraints.gridx = 2;
            constraints.gridy = 5;
            jPanel.add(getBtnSubmit(), constraints);
        }
        return jPanel;
    }

    /**
     * Either 'Add' or 'Save' button.
     *
     * @return
     */
    private JButton getBtnSubmit() {
        if (btnSubmit == null) {
            Dimension size = new Dimension(75, 30);

            btnSubmit = new JButton();
            btnSubmit.setText(getBtnSubmitText());
            btnSubmit.setMinimumSize(size);
            btnSubmit.setPreferredSize(size);
            btnSubmit.setMaximumSize(new Dimension(100, 40));

            btnSubmit.addActionListener(getActionListenerSubmit());
        }
        return btnSubmit;
    }

    private JButton getBtnCancel() {
        if (btnCancel == null) {
            btnCancel = new JButton();
            btnCancel.setText(Constant.messages.getString("brk.add.button.cancel"));
            btnCancel.setMaximumSize(new Dimension(100, 40));
            btnCancel.setMinimumSize(new Dimension(70, 30));
            btnCancel.setPreferredSize(new Dimension(70, 30));
            btnCancel.setEnabled(true);

            btnCancel.addActionListener(getActionListenerCancel());
        }
        return btnCancel;
    }

    private JScrollPane getJScrollPane() {
        if (jScrollPane == null) {
            jScrollPane = new JScrollPane();
            jScrollPane.setHorizontalScrollBarPolicy(
                    javax.swing.JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
            jScrollPane.setVerticalScrollBarPolicy(
                    javax.swing.JScrollPane.VERTICAL_SCROLLBAR_NEVER);
            jScrollPane.setBorder(javax.swing.BorderFactory.createEmptyBorder(0, 0, 0, 0));

            JPanel panel = new JPanel();
            panel.setLayout(new GridBagLayout());

            // Message types
            JLabel jlabel1 = new JLabel(Constant.messages.getString("plugnhack.brk.type.label"));
            jlabel1.setLabelFor(getTypesCombo());
            panel.add(jlabel1, LayoutHelper.getGBC(0, 0, 1, 1.0, 1.0));
            panel.add(getTypesCombo(), LayoutHelper.getGBC(1, 0, 1, 1.0, 1.0));

            // clients
            JLabel jlabel2 = new JLabel(Constant.messages.getString("plugnhack.brk.client.label"));
            jlabel2.setLabelFor(getClientsCombo());
            panel.add(jlabel2, LayoutHelper.getGBC(0, 1, 1, 1.0, 1.0));
            panel.add(getClientsCombo(), LayoutHelper.getGBC(1, 1, 1, 1.0, 1.0));

            JLabel jlabel3 = new JLabel(Constant.messages.getString("plugnhack.brk.payload.label"));
            jlabel3.setLabelFor(getPayloadPattern());
            panel.add(jlabel3, LayoutHelper.getGBC(0, 2, 1, 1.0, 1.0));
            panel.add(getPayloadPattern(), LayoutHelper.getGBC(1, 2, 1, 1.0, 1.0));

            jScrollPane.setViewportView(panel);
        }
        return jScrollPane;
    }

    private JComboBox<String> getTypesCombo() {
        if (typesCombo == null) {
            typesCombo = new JComboBox<>();
            resetTypesCombo();
        }
        return typesCombo;
    }

    private void resetTypesCombo() {
        this.typesCombo.removeAllItems();
        typesCombo.addItem(Constant.messages.getString("plugnhack.brk.types.all"));
        for (String type : extension.getKnownTypes()) {
            if (!MonitoredPagesManager.CLIENT_MESSAGE_TYPE_HEARTBEAT.equalsIgnoreCase(type)) {
                // Dont all option to break on heartbeats - will cause too many problems
                typesCombo.addItem(type);
            }
        }
    }

    private JComboBox<String> getClientsCombo() {
        if (clientsCombo == null) {
            clientsCombo = new JComboBox<>();
            resetClientsCombo();
        }
        return clientsCombo;
    }

    private void resetClientsCombo() {
        this.clientsCombo.removeAllItems();
        clientsCombo.addItem(Constant.messages.getString("plugnhack.brk.clients.all"));
        for (String type : extension.getActiveClientIds()) {
            clientsCombo.addItem(type);
        }
    }

    private JTextField getPayloadPattern() {
        if (payloadPattern == null) {
            payloadPattern = new JTextField();
        }
        return payloadPattern;
    }

    /**
     * @return {@link ClientBreakpointMessage} with values set in dialog
     * @throws PatternSyntaxException
     */
    protected ClientBreakpointMessage getClientBreakpointMessage() throws PatternSyntaxException {
        String type = (String) this.getTypesCombo().getSelectedItem();
        String client = (String) this.getClientsCombo().getSelectedItem();
        if (this.getTypesCombo().getSelectedIndex() == 0) {
            // First option selected - match all types
            type = null;
        }
        if (this.getClientsCombo().getSelectedIndex() == 0) {
            // First option selected - match all clients
            client = null;
        }

        return new ClientBreakpointMessage(type, client, this.getPayloadPattern().getText());
    }

    protected void resetDialogValues() {
        resetTypesCombo();
        resetClientsCombo();
        this.getPayloadPattern().setText("");
    }

    protected void setDialogValues(String type, String client, String payloadPattern) {
        if (client != null) {
            this.getClientsCombo().setSelectedItem(client);
        }
        if (type != null) {
            this.getTypesCombo().setSelectedItem(type);
        }
        if (payloadPattern != null) {
            this.getPayloadPattern().setText(payloadPattern);
        }
    }
}
