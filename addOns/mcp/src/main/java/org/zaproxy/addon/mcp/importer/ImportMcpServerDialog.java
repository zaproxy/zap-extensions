/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.addon.mcp.importer;

import java.awt.Font;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.net.URI;
import java.net.URISyntaxException;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.JTextField;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.AbstractDialog;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.utils.FontUtils;
import org.zaproxy.zap.utils.ThreadUtils;
import org.zaproxy.zap.utils.ZapHtmlLabel;
import org.zaproxy.zap.view.LayoutHelper;

/** Dialog for importing an external MCP server into ZAP's history and sites tree. */
public class ImportMcpServerDialog extends AbstractDialog {

    private static final long serialVersionUID = 1L;

    private JTextField fieldServerUrl;
    private JTextField fieldSecurityKey;
    private JButton buttonCancel;
    private JButton buttonImport;
    private JProgressBar progressBar;

    public ImportMcpServerDialog(JFrame parent) {
        super(parent, true);
        setTitle(Constant.messages.getString("mcp.importserver.dialog.title"));
        centreDialog();
        setLayout(new GridBagLayout());

        var fieldsPanel = new JPanel(new GridBagLayout());
        int fieldsRow = 0;

        fieldsPanel.add(
                new ZapHtmlLabel(
                        "<html>"
                                + Constant.messages.getString(
                                        "mcp.importserver.dialog.serverurl.label")
                                + "<font color=red>*</font></html>"),
                LayoutHelper.getGBC(0, fieldsRow, 1, 0.5, new Insets(0, 0, 4, 4)));
        fieldsPanel.add(
                getServerUrlField(),
                LayoutHelper.getGBC(1, fieldsRow, 1, 0.5, new Insets(0, 4, 4, 0)));
        fieldsRow++;

        fieldsPanel.add(
                new JLabel(
                        Constant.messages.getString("mcp.importserver.dialog.securitykey.label")),
                LayoutHelper.getGBC(0, fieldsRow, 1, 0.5, new Insets(4, 0, 4, 4)));
        fieldsPanel.add(
                getSecurityKeyField(),
                LayoutHelper.getGBC(1, fieldsRow, 1, 0.5, new Insets(4, 4, 4, 0)));

        int row = 0;
        add(fieldsPanel, LayoutHelper.getGBC(0, row, 2, 1.0, new Insets(8, 8, 4, 8)));
        row++;

        var requiredFieldsLabel =
                new ZapHtmlLabel(
                        "<html><font color=red>*</font> "
                                + Constant.messages.getString(
                                        "mcp.importserver.dialog.requiredfields")
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

    private JTextField getServerUrlField() {
        if (fieldServerUrl == null) {
            fieldServerUrl = new JTextField(30);
        }
        return fieldServerUrl;
    }

    private JTextField getSecurityKeyField() {
        if (fieldSecurityKey == null) {
            fieldSecurityKey = new JTextField(30);
        }
        return fieldSecurityKey;
    }

    private JButton getCancelButton() {
        if (buttonCancel == null) {
            buttonCancel = new JButton(Constant.messages.getString("all.button.cancel"));
            buttonCancel.addActionListener(e -> dispose());
        }
        return buttonCancel;
    }

    private JButton getImportButton() {
        if (buttonImport == null) {
            buttonImport =
                    new JButton(
                            Constant.messages.getString("mcp.importserver.dialog.import.button"));
            buttonImport.addActionListener(e -> doImport());
        }
        return buttonImport;
    }

    private JProgressBar getProgressBar() {
        if (progressBar == null) {
            progressBar = new JProgressBar();
            progressBar.setIndeterminate(true);
            progressBar.setVisible(false);
        }
        return progressBar;
    }

    private void doImport() {
        String url = getServerUrlField().getText().trim();
        if (url.isEmpty()) {
            View.getSingleton()
                    .showWarningDialog(
                            this, Constant.messages.getString("mcp.importserver.error.emptyurl"));
            getServerUrlField().requestFocusInWindow();
            return;
        }

        try {
            String scheme = new URI(url).getScheme();
            if (!"http".equals(scheme) && !"https".equals(scheme)) {
                throw new URISyntaxException(url, "Unsupported scheme: " + scheme);
            }
        } catch (URISyntaxException e) {
            View.getSingleton()
                    .showWarningDialog(
                            this,
                            Constant.messages.getString("mcp.importserver.error.invalidurl", url));
            getServerUrlField().requestFocusInWindow();
            return;
        }

        String key = getSecurityKeyField().getText().trim();
        String securityKey = key.isEmpty() ? null : key;

        showProgressBar(true);
        new Thread(
                        () -> {
                            McpImporter importer = new McpImporter();
                            McpImporter.ImportResults results =
                                    importer.importServer(
                                            new McpImporter.ImportConfig(url, securityKey));
                            ThreadUtils.invokeAndWaitHandled(
                                    () -> {
                                        showProgressBar(false);
                                        if (results.errors().isEmpty()) {
                                            dispose();
                                            View.getSingleton()
                                                    .showMessageDialog(
                                                            Constant.messages.getString(
                                                                    "mcp.importserver.dialog.success",
                                                                    results.requestCount()));
                                        } else {
                                            View.getSingleton()
                                                    .showWarningDialog(
                                                            this,
                                                            String.join("\n", results.errors()));
                                            getServerUrlField().requestFocusInWindow();
                                        }
                                    });
                        },
                        "ZAP-Import-MCP-Server")
                .start();
    }

    private void showProgressBar(boolean show) {
        if (getProgressBar().isVisible() == show) {
            return;
        }
        setSize(getWidth(), getHeight() + (show ? 10 : -10));
        getProgressBar().setVisible(show);
        getImportButton().setEnabled(!show);
        getCancelButton().setEnabled(!show);
        getServerUrlField().setEnabled(!show);
        getSecurityKeyField().setEnabled(!show);
    }
}
