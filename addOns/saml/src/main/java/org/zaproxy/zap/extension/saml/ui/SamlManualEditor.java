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
package org.zaproxy.zap.extension.saml.ui;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.FocusEvent;
import java.awt.event.FocusListener;
import java.util.Map;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextField;
import javax.swing.JTextPane;
import javax.swing.border.EmptyBorder;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.saml.Attribute;
import org.zaproxy.zap.extension.saml.SAMLException;
import org.zaproxy.zap.extension.saml.SAMLMessage;
import org.zaproxy.zap.extension.saml.SAMLResender;
import org.zaproxy.zap.extension.saml.SamlI18n;

public class SamlManualEditor extends JFrame {

    private static final long serialVersionUID = 1L;
    private JTextPane msgPane;
    private JButton btnResend;
    private JButton btnReset;
    private SAMLMessage samlMessage;

    private JTextPane respHeadTextPane;
    private JTextPane respBodyTextPane;
    private JTabbedPane tabbedPane;
    private JScrollPane msgScrollPane;
    private JScrollPane attribScrollPane;

    private boolean msgUpdating;

    /** Create the frame. */
    public SamlManualEditor(final SAMLMessage samlMessage) {
        setTitle(SamlI18n.getMessage("saml.editor.title"));
        this.samlMessage = samlMessage;
        setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        setBounds(50, 50, 800, 700);
        JPanel contentPane = new JPanel();
        contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
        contentPane.setLayout(new BorderLayout(0, 0));
        setContentPane(contentPane);

        tabbedPane = new JTabbedPane(JTabbedPane.TOP);
        contentPane.add(tabbedPane, BorderLayout.CENTER);

        final JPanel reqPanel = new JPanel();
        tabbedPane.addTab(SamlI18n.getMessage("saml.editor.tab.request"), null, reqPanel, null);
        reqPanel.setLayout(new BorderLayout(0, 0));

        JPanel topPanel = new JPanel();
        topPanel.setLayout(new FlowLayout(FlowLayout.LEFT));
        reqPanel.add(topPanel, BorderLayout.NORTH);

        JLabel lblNote = new JLabel(SamlI18n.getMessage("saml.editor.headerwarn"));
        topPanel.add(lblNote);

        JPanel centerPanel = new JPanel();
        reqPanel.add(centerPanel, BorderLayout.CENTER);
        centerPanel.setLayout(new GridLayout(2, 1, 0, 10));

        msgScrollPane = new JScrollPane();
        centerPanel.add(msgScrollPane);

        attribScrollPane = new JScrollPane();
        centerPanel.add(attribScrollPane);

        JPanel bottomPanel = new JPanel();
        reqPanel.add(bottomPanel, BorderLayout.SOUTH);

        btnResend = new JButton(SamlI18n.getMessage("saml.editor.btn.resend"));
        bottomPanel.add(btnResend);

        btnReset = new JButton(SamlI18n.getMessage("saml.editor.btn.reset"));
        bottomPanel.add(btnReset);

        btnResend.addActionListener(
                new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent event) {
                        // wait till the message is updated
                        while (msgUpdating) {
                            try {
                                Thread.sleep(50);
                            } catch (InterruptedException ignored) {
                            }
                        }
                        try {
                            SAMLResender.resendMessage(
                                    SamlManualEditor.this.samlMessage.getChangedMessage());
                            updateResponse(SamlManualEditor.this.samlMessage.getChangedMessage());
                            btnResend.setEnabled(false);
                            btnReset.setEnabled(false);
                        } catch (SAMLException e) {
                            JOptionPane.showMessageDialog(
                                    reqPanel,
                                    e.getMessage(),
                                    SamlI18n.getMessage("saml.editor.msg.cantresend"),
                                    JOptionPane.ERROR_MESSAGE);
                        }
                    }
                });
        btnReset.addActionListener(
                new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        SamlManualEditor.this.samlMessage.resetChanges();
                        updateFields();
                    }
                });

        JPanel respPanel = new JPanel();
        tabbedPane.addTab(SamlI18n.getMessage("saml.editor.tab.response"), null, respPanel, null);
        respPanel.setLayout(new GridLayout(2, 1, 0, 15));

        JScrollPane resHeadScrollPane = new JScrollPane();
        respPanel.add(resHeadScrollPane);

        respHeadTextPane = new JTextPane();
        resHeadScrollPane.setViewportView(respHeadTextPane);

        JScrollPane resBodyScrollPane = new JScrollPane();
        respPanel.add(resBodyScrollPane);

        respBodyTextPane = new JTextPane();
        resBodyScrollPane.setViewportView(respBodyTextPane);
        updateFields();
    }

    /** Update the UI fields with the new values. To be called on value changes */
    private void updateFields() {
        msgPane = new JTextPane();
        msgScrollPane.setViewportView(msgPane);
        msgPane.setText(samlMessage.getSamlMessageString());
        msgPane.addFocusListener(
                new FocusListener() {
                    @Override
                    public void focusGained(FocusEvent e) {
                        msgUpdating = true;
                    }

                    @Override
                    public void focusLost(FocusEvent e) {
                        samlMessage.setSamlMessageString(msgPane.getText());
                        // todo: check for validity
                        updateFields();
                        msgUpdating = false;
                    }
                });

        Map<String, Attribute> samlAttributes;
        samlAttributes = samlMessage.getAttributeMap();

        JPanel attributesPane = new JPanel();
        attribScrollPane.setViewportView(attributesPane);

        // 1 row per attribute and 1 for relay state. if the total < 10 set it to 10 to have a
        // better layout
        attributesPane.setLayout(
                new java.awt.GridLayout(Math.max(10, samlAttributes.size() + 1), 1, 5, 5));

        // text field to change relay state
        JSplitPane relayStatePane = new JSplitPane();
        JLabel lblRelayState = new JLabel();
        final JTextField txtRelayStateValue = new JTextField();

        relayStatePane.setDividerLocation(300);
        relayStatePane.setDividerSize(0);

        lblRelayState.setText(SamlI18n.getMessage("saml.editor.relaystate"));
        relayStatePane.setLeftComponent(lblRelayState);

        txtRelayStateValue.setText(samlMessage.getRelayState());
        relayStatePane.setRightComponent(txtRelayStateValue);

        // update the saml message on attribute value changes
        txtRelayStateValue.addFocusListener(
                new FocusListener() {
                    @Override
                    public void focusGained(FocusEvent e) {
                        msgUpdating = true;
                    }

                    @Override
                    public void focusLost(FocusEvent e) {
                        samlMessage.setRelayState(txtRelayStateValue.getText());
                        msgUpdating = false;
                    }
                });
        attributesPane.add(relayStatePane);

        // Text fields to change other attributes

        for (final Attribute attribute : samlAttributes.values()) {
            JSplitPane sPane = new JSplitPane();
            JLabel lbl = new JLabel();
            final JTextField txtValue = new JTextField();

            sPane.setDividerLocation(300);
            sPane.setDividerSize(0);

            lbl.setText(attribute.getViewName());
            sPane.setLeftComponent(lbl);

            txtValue.setText(attribute.getValue().toString());
            sPane.setRightComponent(txtValue);

            // update the saml message on attribute value changes
            txtValue.addFocusListener(
                    new FocusListener() {
                        @Override
                        public void focusGained(FocusEvent e) {
                            msgUpdating = true;
                        }

                        @Override
                        public void focusLost(FocusEvent e) {
                            samlMessage.changeAttributeValueTo(
                                    attribute.getName(), txtValue.getText());
                            msgPane.setText(samlMessage.getSamlMessageString());
                            msgUpdating = false;
                        }
                    });
            attributesPane.add(sPane);
        }
    }

    /**
     * Update the response
     *
     * @param msg
     */
    private void updateResponse(HttpMessage msg) {
        respBodyTextPane.setText(msg.getResponseBody().toString());
        respHeadTextPane.setText(msg.getResponseHeader().toString());
        tabbedPane.setSelectedIndex(1);
    }
}
