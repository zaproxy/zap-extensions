/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2019 The ZAP Development Team
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
package org.zaproxy.zap.extension.jwt.ui;

import java.awt.BorderLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.Arrays;
import java.util.List;
import java.util.function.Consumer;
import java.util.function.Supplier;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.border.EmptyBorder;
import org.zaproxy.zap.extension.fuzz.impl.AddPayloadDialog;
import org.zaproxy.zap.extension.fuzz.impl.PayloadGeneratorsContainer;
import org.zaproxy.zap.extension.fuzz.payloads.ui.impl.FileStringPayloadGeneratorUIHandler;
import org.zaproxy.zap.extension.fuzz.payloads.ui.impl.FileStringPayloadGeneratorUIHandler.FileStringPayloadGeneratorUI;
import org.zaproxy.zap.extension.fuzz.payloads.ui.impl.FileStringPayloadGeneratorUIHandler.FileStringPayloadGeneratorUIPanel;
import org.zaproxy.zap.extension.jwt.JWTConfiguration;
import org.zaproxy.zap.extension.jwt.JWTI18n;

/**
 * @author KSASAN preetkaran20@gmail.com
 * @since TODO add version
 */
public class JWTSettingsUI extends JFrame {

    private static final long serialVersionUID = 1L;

    private JScrollPane settingsScrollPane;
    private JPanel settingsPanel;
    private List<CustomFieldFuzzer> customFieldFuzzers =
            JWTConfiguration.getInstance().getCustomFieldFuzzers();

    public JWTSettingsUI() {
        setTitle(JWTI18n.getMessage("jwt.settings.title"));
        setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        setSize(1000, 400);
        setLocationRelativeTo(null);
        this.addWindowListener(
                new WindowAdapter() {
                    public void windowClosing(WindowEvent we) {
                        JWTConfiguration.getInstance().setCustomFieldFuzzers(customFieldFuzzers);
                    }
                });
        JPanel contentPane = new JPanel();
        contentPane.setBorder(new EmptyBorder(4, 4, 4, 4));
        contentPane.setLayout(new BorderLayout(1, 1));
        setContentPane(contentPane);

        settingsScrollPane = new JScrollPane();
        contentPane.add(settingsScrollPane, BorderLayout.CENTER);
        settingsPanel = new JPanel();
        settingsScrollPane.setViewportView(settingsPanel);
        GridBagLayout gridBagLayout = new GridBagLayout();
        settingsPanel.setLayout(gridBagLayout);
        init();
    }

    private void init() {
        GridBagConstraints gridBagConstraints = new GridBagConstraints();
        gridBagConstraints.fill = GridBagConstraints.NONE;
        gridBagConstraints.anchor = GridBagConstraints.NORTHWEST;
        gridBagConstraints.gridy = 0;
        gridBagConstraints.gridx = 0;
        gridBagConstraints.weightx = 1.0D;
        gridBagConstraints.weighty = 1.0D;

        Insets insets = new Insets(0, 15, 0, 15);
        gridBagConstraints.insets = insets;
        generalSettingsSection(gridBagConstraints);
    }

    private void generalSettingsSection(GridBagConstraints gridBagConstraints) {

        gridBagConstraints.gridy++;
        gridBagConstraints.gridx = 0;
        JLabel lblTargetSelection =
                new JLabel(JWTI18n.getMessage("jwt.settings.general.customFuzz.jwtField.header"));
        settingsPanel.add(lblTargetSelection, gridBagConstraints);

        gridBagConstraints.gridx++;
        JLabel lblFieldName =
                new JLabel(JWTI18n.getMessage("jwt.settings.general.customFuzz.keyField.header"));
        settingsPanel.add(lblFieldName, gridBagConstraints);

        gridBagConstraints.gridx++;
        JLabel lblSignatureRequired =
                new JLabel(JWTI18n.getMessage("jwt.settings.general.customFuzz.signature.header"));
        settingsPanel.add(lblSignatureRequired, gridBagConstraints);

        gridBagConstraints.gridx++;
        JLabel lblSigningKey =
                new JLabel(JWTI18n.getMessage("jwt.settings.general.customFuzz.signingKey.header"));
        settingsPanel.add(lblSigningKey, gridBagConstraints);

        gridBagConstraints.gridx++;
        JLabel lblPayload =
                new JLabel(JWTI18n.getMessage("jwt.settings.general.customFuzz.payload.header"));
        settingsPanel.add(lblPayload, gridBagConstraints);

        gridBagConstraints.gridx++;
        JButton addCustomFuzzFields =
                new JButton(JWTI18n.getMessage("jwt.settings.general.customFuzz.addFuzzFields"));
        settingsPanel.add(addCustomFuzzFields, gridBagConstraints);
        addCustomFuzzFields.addActionListener(
                new ActionListener() {

                    @Override
                    public void actionPerformed(ActionEvent e) {
                        Insets insets = new Insets(5, 15, 5, 15);
                        gridBagConstraints.insets = insets;
                        renderCustomFuzzFields(gridBagConstraints, new CustomFieldFuzzer());
                    }
                });

        for (CustomFieldFuzzer customFieldFuzzer : this.customFieldFuzzers) {
            Insets insets = new Insets(5, 15, 5, 15);
            gridBagConstraints.insets = insets;
            renderCustomFuzzFields(gridBagConstraints, customFieldFuzzer);
        }
    }

    private void showAddPayloadDialog(
            Supplier<FileStringPayloadGeneratorUI> getFileStringPayloadGeneratorUISupplier,
            Consumer<FileStringPayloadGeneratorUI> setFileStringPayloadGeneratorUIConsumer) {
        FileStringPayloadGeneratorUIHandler payloadGeneratorUIHandler =
                new FileStringPayloadGeneratorUIHandler();
        PayloadGeneratorsContainer payloadGeneratorsContainer =
                new PayloadGeneratorsContainer(
                        Arrays.asList(payloadGeneratorUIHandler), "JWT Fuzzer");
        if (getFileStringPayloadGeneratorUISupplier.get() != null) {
            ((FileStringPayloadGeneratorUIPanel)
                            payloadGeneratorsContainer.getPanel(
                                    payloadGeneratorUIHandler.getName()))
                    .populateFileStringPayloadGeneratorUIPanel(
                            getFileStringPayloadGeneratorUISupplier.get());
        }
        AddPayloadDialog jwtAddPayloadDialog =
                new AddPayloadDialog(this, payloadGeneratorsContainer, null) {
                    private static final long serialVersionUID = 1L;

                    @Override
                    protected void performAction() {
                        super.performAction();
                        setFileStringPayloadGeneratorUIConsumer.accept(
                                (FileStringPayloadGeneratorUI) getPayloadGeneratorUI());
                    }

                    @Override
                    protected void clearFields() {
                        super.clearFields();
                    }
                };
        jwtAddPayloadDialog.pack();
        jwtAddPayloadDialog.setVisible(true);
    }

    private void renderCustomFuzzFields(
            GridBagConstraints gridBagConstraints, CustomFieldFuzzer customFieldFuzzer) {
        gridBagConstraints.gridy++;
        gridBagConstraints.gridx = 0;
        JComboBox<String> headerOrPayload =
                new JComboBox<String>(
                        new String[] {
                            JWTI18n.getMessage("jwt.settings.general.customFuzz.tokenHeader"),
                            JWTI18n.getMessage("jwt.settings.general.customFuzz.tokenPayload")
                        });
        headerOrPayload.setSelectedIndex(0);
        headerOrPayload.setSelectedIndex(customFieldFuzzer.isHeaderField() ? 0 : 1);
        settingsPanel.add(headerOrPayload, gridBagConstraints);

        gridBagConstraints.gridx++;
        JTextField fieldName = new JTextField();
        fieldName.setColumns(10);
        fieldName.setText(customFieldFuzzer.getFieldName());
        settingsPanel.add(fieldName, gridBagConstraints);

        gridBagConstraints.gridx++;
        JCheckBox signatureRequired = new JCheckBox();
        signatureRequired.setSelected(customFieldFuzzer.isSignatureRequired());
        settingsPanel.add(signatureRequired, gridBagConstraints);

        gridBagConstraints.gridx++;
        JTextArea signingKey = new JTextArea(10, 25);
        signingKey.setText(customFieldFuzzer.getSigningKey());
        settingsPanel.add(signingKey, gridBagConstraints);

        gridBagConstraints.gridx++;
        JButton addPayload =
                new JButton(JWTI18n.getMessage("jwt.settings.general.customFuzz.addPayload"));
        settingsPanel.add(addPayload, gridBagConstraints);
        addPayload.addActionListener(
                new ActionListener() {

                    @Override
                    public void actionPerformed(ActionEvent e) {
                        Consumer<FileStringPayloadGeneratorUI> customFieldFuzzerConsumer =
                                (FileStringPayloadGeneratorUI) ->
                                        customFieldFuzzer.setFileStringPayloadGeneratorUI(
                                                FileStringPayloadGeneratorUI);
                        Supplier<FileStringPayloadGeneratorUI> customFieldFuzzerSupplier =
                                () -> customFieldFuzzer.getFileStringPayloadGeneratorUI();
                        showAddPayloadDialog(customFieldFuzzerSupplier, customFieldFuzzerConsumer);
                    }
                });

        gridBagConstraints.gridx++;
        JButton saveButton =
                new JButton(JWTI18n.getMessage("jwt.settings.general.customFuzz.saveFuzzFields"));
        settingsPanel.add(saveButton, gridBagConstraints);

        gridBagConstraints.gridx++;
        JButton removeButton =
                new JButton(JWTI18n.getMessage("jwt.settings.general.customFuzz.removeFuzzFields"));
        settingsPanel.add(removeButton, gridBagConstraints);
        removeButton.addActionListener(
                new ActionListener() {

                    @Override
                    public void actionPerformed(ActionEvent e) {
                        int index = customFieldFuzzers.indexOf(customFieldFuzzer);
                        if (index >= 0) {
                            customFieldFuzzers.remove(customFieldFuzzer);
                        }
                        settingsPanel.remove(headerOrPayload);
                        settingsPanel.remove(fieldName);
                        settingsPanel.remove(removeButton);
                        settingsPanel.remove(signatureRequired);
                        settingsPanel.remove(saveButton);
                        settingsPanel.remove(addPayload);
                        settingsPanel.remove(signingKey);
                        settingsScrollPane.revalidate();
                    }
                });

        saveButton.addActionListener(
                new ActionListener() {

                    @Override
                    public void actionPerformed(ActionEvent e) {
                        customFieldFuzzer.setFieldName(fieldName.getText());
                        customFieldFuzzer.setHeaderField(headerOrPayload.getSelectedIndex() == 0);
                        customFieldFuzzer.setSignatureRequired(signatureRequired.isSelected());
                        customFieldFuzzer.setSigningKey(signingKey.getText());
                        customFieldFuzzer.setFileStringPayloadGeneratorUI(
                                customFieldFuzzer.getFileStringPayloadGeneratorUI());
                        customFieldFuzzers.add(customFieldFuzzer);
                    }
                });

        settingsScrollPane.revalidate();
    }
}
