/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
package org.zaproxy.zap.extension.openapi.llm;

import java.awt.Font;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.io.File;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JProgressBar;
import javax.swing.JTextField;
import javax.swing.SwingConstants;
import javax.swing.filechooser.FileNameExtensionFilter;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.commons.lang3.StringUtils;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.AbstractDialog;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.llm.ExtensionLlm;
import org.zaproxy.addon.llm.services.LlmCommunicationService;
import org.zaproxy.zap.utils.FontUtils;
import org.zaproxy.zap.utils.ThreadUtils;
import org.zaproxy.zap.utils.ZapHtmlLabel;
import org.zaproxy.zap.view.LayoutHelper;

@SuppressWarnings("serial")
public class LlmOpenApiImportDialog extends AbstractDialog {

    private static final long serialVersionUID = -7074394202143400215L;

    private JTextField fieldOpenapi;
    private JButton buttonChooseFile;
    private JButton buttonCancel;
    private JButton buttonImport;
    private JProgressBar progressBar;

    public LlmOpenApiImportDialog(JFrame parent, ExtensionOpenApiLlm ext) {
        super(parent, true);

        super.setTitle(Constant.messages.getString("openapi.llm.importDialog.title"));
        centreDialog();
        setLayout(new GridBagLayout());

        var fieldsPanel = new JPanel(new GridBagLayout());
        int fieldsRow = 0;

        var labelWsdl =
                new ZapHtmlLabel(
                        "<html>"
                                + Constant.messages.getString(
                                        "openapi.llm.importDialog.labelOpenAPI")
                                + "<font color=red>*</font></html>");
        fieldsPanel.add(
                labelWsdl, LayoutHelper.getGBC(0, fieldsRow, 1, 0.5, new Insets(0, 0, 4, 4)));
        fieldsPanel.add(
                getOpenapiField(),
                LayoutHelper.getGBC(1, fieldsRow, 1, 0.5, new Insets(0, 4, 4, 4)));
        fieldsPanel.add(
                getChooseFileButton(),
                LayoutHelper.getGBC(2, fieldsRow, 1, 0.5, new Insets(0, 4, 4, 0)));

        int row = 0;
        add(fieldsPanel, LayoutHelper.getGBC(0, row, 2, 1.0, new Insets(8, 8, 4, 8)));
        row++;
        var requiredFieldsLabel =
                new ZapHtmlLabel(
                        "<html><font color=red>*</font> "
                                + Constant.messages.getString(
                                        "openapi.llm.importDialog.requiredFields")
                                + "</html>");
        Font font = requiredFieldsLabel.getFont();
        requiredFieldsLabel.setFont(FontUtils.getFont(font, FontUtils.Size.much_smaller));
        requiredFieldsLabel.setHorizontalAlignment(SwingConstants.RIGHT);
        add(requiredFieldsLabel, LayoutHelper.getGBC(0, row, 2, 1.0, new Insets(4, 8, 4, 8)));
        row++;
        add(getCancelButton(), LayoutHelper.getGBC(0, row, 1, 0.5, new Insets(4, 8, 8, 4)));
        add(getImportButton(), LayoutHelper.getGBC(1, row, 1, 0.5, new Insets(4, 4, 8, 8)));
        row++;
        add(getProgressBar(), LayoutHelper.getGBC(0, row, 2, 1.0, new Insets(0, 8, 8, 8)));
        pack();
        setDefaultCloseOperation(DISPOSE_ON_CLOSE);
    }

    private boolean importOpenapi() {

        String openapiLocation = getOpenapiField().getText();
        Integer endpointCount = 0;

        ExtensionLlm extLlm = getExtensionLlm();
        if (!extLlm.isConfigured()) {
            showWarningDialog(
                    Constant.messages.getString("openapi.llm.importDialog.error.llmNotConfigured"));
            return false;
        }

        LlmCommunicationService llmCommunicationService =
                extLlm.getCommunicationService(
                        "OPENAPI",
                        Constant.messages.getString("openapi.llm.openapi.import.output.tab"));

        if (llmCommunicationService == null) {
            showWarningDialog(
                    Constant.messages.getString("openapi.llm.importDialog.error.llmNotConfigured"));
            return false;
        }

        if (StringUtils.isEmpty(openapiLocation)) {
            ThreadUtils.invokeAndWaitHandled(
                    () -> {
                        showWarningDialog(
                                Constant.messages.getString(
                                        "openapi.llm.importDialog.error.missingOpenAPI"));
                        getOpenapiField().requestFocusInWindow();
                    });
            return false;
        }

        if (isValidURL(openapiLocation)) {
            endpointCount = llmCommunicationService.importOpenapiFromUrl(openapiLocation);
        } else if (new File(openapiLocation).canRead()) {
            endpointCount = llmCommunicationService.importOpenapiFromFile(openapiLocation);
        } else {
            ThreadUtils.invokeAndWaitHandled(
                    () -> {
                        showWarningFileNotFound(openapiLocation);
                        getOpenapiField().requestFocusInWindow();
                    });
            return false;
        }

        if (endpointCount > 0) {
            showMessageDialog(
                    Constant.messages.getString(
                            "openapi.llm.importDialog.import.success", endpointCount));
            return true;
        } else {
            showWarningDialog(
                    Constant.messages.getString("openapi.llm.importDialog.import.failure"));
            return false;
        }
    }

    private ExtensionLlm getExtensionLlm() {
        return Control.getSingleton().getExtensionLoader().getExtension(ExtensionLlm.class);
    }

    private static void setContextMenu(JTextField field) {
        JMenuItem paste =
                new JMenuItem(Constant.messages.getString("openapi.llm.importDialog.pasteAction"));
        paste.addActionListener(e -> field.paste());

        JPopupMenu jPopupMenu = new JPopupMenu();
        jPopupMenu.add(paste);
        field.setComponentPopupMenu(jPopupMenu);
    }

    private JTextField getOpenapiField() {
        if (fieldOpenapi == null) {
            fieldOpenapi = new JTextField(25);
            setContextMenu(fieldOpenapi);
        }
        return fieldOpenapi;
    }

    private JButton getChooseFileButton() {
        if (buttonChooseFile == null) {
            buttonChooseFile =
                    new JButton(
                            Constant.messages.getString(
                                    "openapi.llm.importDialog.chooseFileButton"));
            buttonChooseFile.addActionListener(
                    e -> {
                        JFileChooser fileChooser =
                                new JFileChooser(
                                        Model.getSingleton().getOptionsParam().getUserDirectory());
                        FileNameExtensionFilter filter =
                                new FileNameExtensionFilter(
                                        Constant.messages.getString(
                                                "openapi.llm.importDialog.fileFilterDescription"),
                                        "json",
                                        "yaml");
                        fileChooser.setFileFilter(filter);
                        if (fileChooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
                            String filename = fileChooser.getSelectedFile().getAbsolutePath();
                            try {
                                getOpenapiField().setText(filename);
                                Model.getSingleton()
                                        .getOptionsParam()
                                        .setUserDirectory(fileChooser.getCurrentDirectory());
                            } catch (Exception e1) {
                                showWarningFileNotFound(filename);
                            }
                        }
                    });
        }
        return buttonChooseFile;
    }

    private JButton getCancelButton() {
        if (buttonCancel == null) {
            buttonCancel = new JButton(Constant.messages.getString("all.button.cancel"));
            buttonCancel.addActionListener(
                    e -> {
                        dispose();
                        showProgressBar(false);
                    });
        }
        return buttonCancel;
    }

    private JButton getImportButton() {
        if (buttonImport == null) {
            buttonImport =
                    new JButton(
                            Constant.messages.getString("openapi.llm.importDialog.importButton"));
            buttonImport.addActionListener(
                    e -> {
                        showProgressBar(true);
                        new Thread(
                                        () -> {
                                            try {
                                                if (importOpenapi()) {
                                                    ThreadUtils.invokeAndWaitHandled(
                                                            () -> {
                                                                dispose();
                                                                showProgressBar(false);
                                                            });
                                                } else {
                                                    showProgressBar(false);
                                                }
                                            } catch (Exception ex) {
                                                ThreadUtils.invokeAndWaitHandled(
                                                        () -> showProgressBar(false));
                                                throw new RuntimeException(ex);
                                            }
                                        },
                                        "ZAP-OpenAPI-LLM-Import")
                                .start();
                    });
        }
        return buttonImport;
    }

    public void showWarningFileNotFound(String fileLocation) {
        showWarningDialog(
                Constant.messages.getString(
                        "openapi.llm.importDialog.error.fileNotFound", fileLocation));
    }

    public void showWarningDialog(String message) {
        showProgressBar(false);
        View.getSingleton().showWarningDialog(this, message);
    }

    public void showMessageDialog(String message) {
        showProgressBar(false);
        View.getSingleton().showMessageDialog(this, message);
    }

    private void showProgressBar(boolean show) {
        if (getProgressBar().isVisible() == show) {
            return;
        }

        setSize(getWidth(), getHeight() + (show ? 10 : -10));
        getProgressBar().setVisible(show);

        getImportButton().setEnabled(!show);
        getOpenapiField().setEnabled(!show);
        getChooseFileButton().setEnabled(!show);
    }

    private JProgressBar getProgressBar() {
        if (progressBar == null) {
            progressBar = new JProgressBar();
            progressBar.setIndeterminate(true);
            progressBar.setVisible(false);
        }
        return progressBar;
    }

    public void clearFields() {
        getOpenapiField().setText("");
    }

    private boolean isValidURL(String url) {
        try {
            new java.net.URI(url).toURL();
            new URI(url, true);
        } catch (URIException | MalformedURLException | URISyntaxException e) {
            // Not a valid URI
            return false;
        }
        return true;
    }
}
