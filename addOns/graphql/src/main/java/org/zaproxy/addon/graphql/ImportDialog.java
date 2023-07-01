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
package org.zaproxy.addon.graphql;

import java.awt.Font;
import java.awt.GridBagLayout;
import java.awt.Insets;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JProgressBar;
import javax.swing.JTextField;
import org.apache.commons.httpclient.URIException;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.AbstractDialog;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpSender;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.utils.FontUtils;
import org.zaproxy.zap.utils.ThreadUtils;
import org.zaproxy.zap.utils.ZapHtmlLabel;
import org.zaproxy.zap.view.LayoutHelper;

@SuppressWarnings("serial")
public class ImportDialog extends AbstractDialog {

    private static final long serialVersionUID = 1L;
    private static final String MESSAGE_PREFIX = "graphql.importDialog.";

    private JTextField fieldSchema;
    private JTextField fieldEndpoint;
    private GraphQlParser parser;
    private JButton buttonCancel;
    private JButton buttonChooseFile;
    private JButton buttonImport;
    private JProgressBar progressBar;

    public ImportDialog(JFrame parent) {
        super(parent, true);
        setTitle(Constant.messages.getString(MESSAGE_PREFIX + "title"));
        centreDialog();
        setLayout(new GridBagLayout());

        var fieldsPanel = new JPanel(new GridBagLayout());
        int fieldsRow = 0;
        fieldsPanel.add(
                new JLabel(Constant.messages.getString(MESSAGE_PREFIX + "labelSchema")),
                LayoutHelper.getGBC(0, fieldsRow, 1, 0.5, new Insets(0, 0, 4, 4)));
        fieldsPanel.add(
                getSchemaField(),
                LayoutHelper.getGBC(1, fieldsRow, 1, 0.5, new Insets(0, 4, 4, 4)));
        fieldsPanel.add(
                getChooseFileButton(),
                LayoutHelper.getGBC(2, fieldsRow, 1, 0.5, new Insets(0, 4, 4, 0)));
        fieldsRow++;
        var endpointLabel =
                new ZapHtmlLabel(
                        "<html>"
                                + Constant.messages.getString(MESSAGE_PREFIX + "labelEndpoint")
                                + "<font color=red>*</font></html>");
        fieldsPanel.add(
                endpointLabel, LayoutHelper.getGBC(0, fieldsRow, 1, 0.5, new Insets(4, 0, 0, 4)));
        fieldsPanel.add(
                getEndpointField(),
                LayoutHelper.getGBC(1, fieldsRow, 2, 0.5, new Insets(4, 4, 0, 0)));

        int row = 0;
        add(fieldsPanel, LayoutHelper.getGBC(0, row, 2, 1.0, new Insets(8, 8, 4, 8)));
        row++;
        var requiredFieldsLabel =
                new ZapHtmlLabel(
                        "<html><font color=red>*</font> "
                                + Constant.messages.getString(MESSAGE_PREFIX + "requiredFields")
                                + "</html>");
        Font font = requiredFieldsLabel.getFont();
        requiredFieldsLabel.setFont(FontUtils.getFont(font, FontUtils.Size.much_smaller));
        requiredFieldsLabel.setHorizontalAlignment(JLabel.RIGHT);
        add(requiredFieldsLabel, LayoutHelper.getGBC(0, row, 2, 1.0, new Insets(4, 8, 4, 8)));
        row++;
        add(getCancelButton(), LayoutHelper.getGBC(0, row, 1, 0.5, new Insets(4, 8, 8, 4)));
        add(getImportButton(), LayoutHelper.getGBC(1, row, 1, 0.5, new Insets(4, 4, 8, 8)));
        row++;
        add(getProgressBar(), LayoutHelper.getGBC(0, row, 2, 1.0, new Insets(0, 8, 8, 8)));
        pack();
        setDefaultCloseOperation(DISPOSE_ON_CLOSE);
    }

    private JTextField getSchemaField() {
        if (fieldSchema == null) {
            fieldSchema = new JTextField(25);
            setContextMenu(fieldSchema);
        }
        return fieldSchema;
    }

    private JTextField getEndpointField() {
        if (fieldEndpoint == null) {
            fieldEndpoint = new JTextField(25);
            setContextMenu(fieldEndpoint);
        }
        return fieldEndpoint;
    }

    private JButton getImportButton() {
        if (buttonImport == null) {
            buttonImport =
                    new JButton(Constant.messages.getString(MESSAGE_PREFIX + "importButton"));
            buttonImport.addActionListener(
                    e -> {
                        showProgressBar(true);
                        new Thread(
                                        () -> {
                                            if (validateEndpointUrl() && importDefinition()) {
                                                ThreadUtils.invokeAndWaitHandled(
                                                        () -> {
                                                            dispose();
                                                            showProgressBar(false);
                                                        });
                                            }
                                        },
                                        "ZAP-GraphQL-UI-Import")
                                .start();
                    });
        }
        return buttonImport;
    }

    private JButton getCancelButton() {
        if (buttonCancel == null) {
            buttonCancel = new JButton(Constant.messages.getString("all.button.cancel"));
            buttonCancel.addActionListener(e -> dispose());
        }
        return buttonCancel;
    }

    private JProgressBar getProgressBar() {
        if (progressBar == null) {
            progressBar = new JProgressBar();
            progressBar.setIndeterminate(true);
            progressBar.setVisible(false);
        }
        return progressBar;
    }

    private void showProgressBar(boolean show) {
        setSize(getWidth(), getHeight() + (show ? 10 : -10));
        getProgressBar().setVisible(show);

        getImportButton().setEnabled(!show);
        getSchemaField().setEnabled(!show);
        getEndpointField().setEnabled(!show);
        getChooseFileButton().setEnabled(!show);
    }

    private boolean validateEndpointUrl() {
        try {
            parser =
                    new GraphQlParser(
                            fieldEndpoint.getText(), HttpSender.MANUAL_REQUEST_INITIATOR, false);
            parser.addRequesterListener(new HistoryPersister());
            return true;
        } catch (URIException e) {
            ThreadUtils.invokeAndWaitHandled(
                    () -> {
                        showWarningDialog(
                                Constant.messages.getString(
                                        "graphql.error.invalidurl", e.getMessage()));
                        fieldEndpoint.requestFocusInWindow();
                    });
        }
        return false;
    }

    private JButton getChooseFileButton() {
        if (buttonChooseFile == null) {
            buttonChooseFile =
                    new JButton(Constant.messages.getString(MESSAGE_PREFIX + "chooseFileButton"));
            buttonChooseFile.addActionListener(
                    e -> {
                        JFileChooser filechooser =
                                new JFileChooser(
                                        Model.getSingleton().getOptionsParam().getUserDirectory());
                        int state = filechooser.showOpenDialog(this);
                        if (state == JFileChooser.APPROVE_OPTION) {
                            String filename = filechooser.getSelectedFile().getAbsolutePath();
                            try {
                                getSchemaField().setText(filename);
                                Model.getSingleton()
                                        .getOptionsParam()
                                        .setUserDirectory(filechooser.getCurrentDirectory());
                            } catch (Exception e1) {
                                showWarningDialog(
                                        Constant.messages.getString(
                                                "graphql.error.filenotfound", filename));
                            }
                        }
                    });
        }
        return buttonChooseFile;
    }

    private boolean importDefinition() {
        String schemaLocation = getSchemaField().getText();
        try {
            if (schemaLocation == null || schemaLocation.isEmpty()) {
                getParser().introspect();
            } else if (UrlBuilder.isValidUrl(schemaLocation)) {
                getParser().importUrl(schemaLocation);
            } else {
                getParser().importFile(schemaLocation);
            }
            return true;
        } catch (Exception e) {
            ThreadUtils.invokeAndWaitHandled(
                    () -> {
                        showWarningDialog(
                                Constant.messages.getString(
                                        "graphql.error.import", e.getMessage()));
                        if (schemaLocation == null || schemaLocation.isEmpty()) {
                            fieldEndpoint.requestFocusInWindow();
                        } else {
                            fieldSchema.requestFocusInWindow();
                        }
                    });
        }
        return false;
    }

    private void showWarningDialog(String message) {
        showProgressBar(false);
        View.getSingleton().showWarningDialog(this, message);
    }

    private GraphQlParser getParser() {
        return parser;
    }

    private static void setContextMenu(JTextField field) {
        JMenuItem paste =
                new JMenuItem(Constant.messages.getString(MESSAGE_PREFIX + "pasteAction"));
        paste.addActionListener(e -> field.paste());

        JPopupMenu jPopupMenu = new JPopupMenu();
        jPopupMenu.add(paste);
        field.setComponentPopupMenu(jPopupMenu);
    }

    void clearFields() {
        getSchemaField().setText("");
        getEndpointField().setText("");
    }
}
