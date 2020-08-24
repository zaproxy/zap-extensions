/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
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
package org.zaproxy.addon.graphql;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;
import javax.swing.JTextField;
import org.apache.commons.httpclient.URIException;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.AbstractDialog;
import org.parosproxy.paros.network.HttpSender;
import org.parosproxy.paros.view.View;

abstract class ImportFromAbstractDialog extends AbstractDialog {

    private static final long serialVersionUID = 1L;
    private static final String MESSAGE_PREFIX = "graphql.importfromdialog.";

    private final JTextField fieldSchema = new JTextField(35);
    private final JTextField fieldEndpoint = new JTextField(35);
    private GraphQlParser parser;

    public ImportFromAbstractDialog(JFrame parent, String title, String schemaFieldLabel) {
        super(parent, true);
        this.setTitle(title);
        centreDialog();

        setLayout(new GridBagLayout());
        GridBagConstraints constraints = new GridBagConstraints();
        constraints.anchor = GridBagConstraints.WEST;
        constraints.insets = new Insets(5, 5, 5, 5);

        JButton buttonImport =
                new JButton(Constant.messages.getString(MESSAGE_PREFIX + "importbutton"));
        buttonImport.addActionListener(
                e -> {
                    if (validateEndpointUrl() && importDefinition()) {
                        setVisible(false);
                        dispose();
                    }
                });
        JButton buttonCancel = new JButton(Constant.messages.getString("all.button.cancel"));
        buttonCancel.addActionListener(
                e -> {
                    setVisible(false);
                    dispose();
                });

        constraints.gridx = 0;
        constraints.gridy = 0;
        add(new JLabel(schemaFieldLabel), constraints);

        constraints.gridx = 1;
        constraints.fill = GridBagConstraints.HORIZONTAL;
        constraints.weightx = 1.0;
        constraints.gridwidth = 3;
        setContextMenu(fieldSchema);
        addSchemaFields(constraints);

        constraints.weightx = 0;
        constraints.gridwidth = 1;
        constraints.gridx = 0;
        constraints.gridy = 1;
        add(new JLabel(Constant.messages.getString(MESSAGE_PREFIX + "labelendpoint")), constraints);

        constraints.gridx = 1;
        constraints.fill = GridBagConstraints.HORIZONTAL;
        constraints.weightx = 1.0;
        constraints.gridwidth = 3;
        setContextMenu(fieldEndpoint);
        add(fieldEndpoint, constraints);

        constraints.gridwidth = 1;
        constraints.gridx = 2;
        constraints.gridy = 2;
        constraints.anchor = GridBagConstraints.CENTER;
        add(buttonCancel, constraints);
        constraints.gridx = 3;
        constraints.anchor = GridBagConstraints.CENTER;
        add(buttonImport, constraints);

        setDefaultCloseOperation(DISPOSE_ON_CLOSE);
        pack();
        setVisible(true);
    }

    protected boolean validateEndpointUrl() {
        try {
            parser =
                    new GraphQlParser(fieldEndpoint.getText(), HttpSender.MANUAL_REQUEST_INITIATOR);
            parser.addRequesterListener(new HistoryPersister());
            return true;
        } catch (URIException e) {
            showWarningDialog(
                    Constant.messages.getString("graphql.error.invalidurl", e.getMessage()));
            fieldEndpoint.requestFocusInWindow();
        }
        return false;
    }

    protected void addSchemaFields(GridBagConstraints constraints) {
        add(fieldSchema, constraints);
    }

    protected abstract boolean importDefinition();

    protected void showWarningDialog(String message) {
        View.getSingleton().showWarningDialog(this, message);
    }

    protected JTextField getSchemaField() {
        return fieldSchema;
    }

    protected JTextField getEndpointField() {
        return fieldEndpoint;
    }

    protected GraphQlParser getParser() {
        return parser;
    }

    private static void setContextMenu(JTextField field) {
        JMenuItem paste =
                new JMenuItem(Constant.messages.getString(MESSAGE_PREFIX + "pasteaction"));
        paste.addActionListener(e -> field.paste());

        JPopupMenu jPopupMenu = new JPopupMenu();
        jPopupMenu.add(paste);
        field.setComponentPopupMenu(jPopupMenu);
    }
}
