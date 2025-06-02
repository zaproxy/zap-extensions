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
package org.zaproxy.zap.extension.fuzz.payloads.ui.impl;

import java.awt.event.ItemEvent;
import java.util.List;
import javax.swing.GroupLayout;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.zaproxy.zap.extension.fuzz.ScriptUIEntry;
import org.zaproxy.zap.extension.fuzz.payloads.DefaultPayload;
import org.zaproxy.zap.extension.fuzz.payloads.generator.PayloadGenerator;
import org.zaproxy.zap.extension.fuzz.payloads.generator.ScriptStringPayloadGenerator;
import org.zaproxy.zap.extension.fuzz.payloads.generator.ScriptStringPayloadGeneratorAdapter;
import org.zaproxy.zap.extension.fuzz.payloads.ui.PayloadGeneratorUI;
import org.zaproxy.zap.extension.fuzz.payloads.ui.PayloadGeneratorUIHandler;
import org.zaproxy.zap.extension.fuzz.payloads.ui.impl.ScriptStringPayloadGeneratorAdapterUIHandler.ScriptStringPayloadGeneratorAdapterUI;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.model.MessageLocation;
import org.zaproxy.zap.utils.FontUtils;
import org.zaproxy.zap.utils.ResettableAutoCloseableIterator;
import org.zaproxy.zap.utils.SortedComboBoxModel;

public class ScriptStringPayloadGeneratorAdapterUIHandler
        implements PayloadGeneratorUIHandler<
                DefaultPayload,
                ScriptStringPayloadGeneratorAdapter,
                ScriptStringPayloadGeneratorAdapterUI> {

    private static final Logger LOGGER =
            LogManager.getLogger(ScriptStringPayloadGeneratorAdapterUIHandler.class);

    private static final String PAYLOAD_GENERATOR_NAME =
            Constant.messages.getString("fuzz.payloads.generator.script.name");

    private final ExtensionScript extensionScript;

    public ScriptStringPayloadGeneratorAdapterUIHandler(ExtensionScript extensionScript) {
        this.extensionScript = extensionScript;
    }

    @Override
    public String getName() {
        return PAYLOAD_GENERATOR_NAME;
    }

    @Override
    public Class<ScriptStringPayloadGeneratorAdapterUI> getPayloadGeneratorUIClass() {
        return ScriptStringPayloadGeneratorAdapterUI.class;
    }

    @Override
    public Class<ScriptStringPayloadGeneratorAdapterUIPanel> getPayloadGeneratorUIPanelClass() {
        return ScriptStringPayloadGeneratorAdapterUIPanel.class;
    }

    @Override
    public ScriptStringPayloadGeneratorAdapterUIPanel createPanel() {
        return new ScriptStringPayloadGeneratorAdapterUIPanel(
                extensionScript.getScripts(ScriptStringPayloadGenerator.TYPE_NAME));
    }

    public static class ScriptStringPayloadGeneratorAdapterUI
            implements PayloadGeneratorUI<DefaultPayload, ScriptStringPayloadGeneratorAdapter> {

        private final ScriptWrapper scriptWrapper;
        private ScriptStringPayloadGenerator scriptPayloadGenerator;

        public ScriptStringPayloadGeneratorAdapterUI(
                ScriptWrapper scriptWrapper, ScriptStringPayloadGenerator scriptPayloadGenerator) {
            this.scriptWrapper = scriptWrapper;
            this.scriptPayloadGenerator = scriptPayloadGenerator;
        }

        public ScriptWrapper getScriptWrapper() {
            return scriptWrapper;
        }

        public ScriptStringPayloadGenerator getScriptStringPayloadGenerator() {
            return scriptPayloadGenerator;
        }

        @Override
        public Class<ScriptStringPayloadGeneratorAdapter> getPayloadGeneratorClass() {
            return ScriptStringPayloadGeneratorAdapter.class;
        }

        @Override
        public String getName() {
            return PAYLOAD_GENERATOR_NAME;
        }

        @Override
        public String getDescription() {
            return scriptWrapper.getName();
        }

        @Override
        public long getNumberOfPayloads() {
            try {
                return scriptPayloadGenerator.getNumberOfPayloads();
            } catch (Exception e) {
                LOGGER.warn(
                        "Failed to obtain number of payloads from script '{}':",
                        scriptWrapper.getName(),
                        e);
            }
            return PayloadGenerator.UNKNOWN_NUMBER_OF_PAYLOADS;
        }

        @Override
        public ScriptStringPayloadGeneratorAdapter getPayloadGenerator() {
            return new ScriptStringPayloadGeneratorAdapter(scriptWrapper, scriptPayloadGenerator);
        }

        @Override
        public ScriptStringPayloadGeneratorAdapterUI copy() {
            return this;
        }
    }

    public static class ScriptStringPayloadGeneratorAdapterUIPanel
            extends AbstractPersistentPayloadGeneratorUIPanel<
                    DefaultPayload,
                    ScriptStringPayloadGeneratorAdapter,
                    ScriptStringPayloadGeneratorAdapterUI> {

        private static final int MAX_NUMBER_PAYLOADS_PREVIEW = 250;

        private static final String SCRIPT_FIELD_LABEL =
                Constant.messages.getString("fuzz.payloads.generator.script.script.label");
        private static final String PAYLOADS_PREVIEW_FIELD_LABEL =
                Constant.messages.getString("fuzz.payloads.generator.script.payloadsPreview.label");
        private static final String PAYLOADS_PREVIEW_GENERATE_FIELD_LABEL =
                Constant.messages.getString(
                        "fuzz.payloads.generator.script.payloadsPreviewGenerate.label");

        private JPanel fieldsPanel;
        private final JComboBox<ScriptUIEntry> scriptComboBox;

        private JTextArea payloadsPreviewTextArea;
        private JButton payloadsPreviewGenerateButton;

        public ScriptStringPayloadGeneratorAdapterUIPanel(List<ScriptWrapper> scriptWrappers) {
            scriptComboBox = new JComboBox<>(new SortedComboBoxModel<ScriptUIEntry>());
            for (ScriptWrapper scriptWrapper : scriptWrappers) {
                if (scriptWrapper.isEnabled()) {
                    scriptComboBox.addItem(new PayloadGeneratorScriptUIEntry(scriptWrapper));
                }
            }
            scriptComboBox.addItemListener(
                    e -> {
                        if (e.getStateChange() == ItemEvent.SELECTED) {
                            updatePreviewFor((PayloadGeneratorScriptUIEntry) e.getItem());
                        }
                    });
            setPreviewAndSaveButtonsEnabled(scriptComboBox.getSelectedIndex() >= 0);

            fieldsPanel = new JPanel();

            GroupLayout layout = new GroupLayout(fieldsPanel);
            fieldsPanel.setLayout(layout);
            layout.setAutoCreateGaps(true);

            JLabel scriptLabel = new JLabel(SCRIPT_FIELD_LABEL);
            scriptLabel.setLabelFor(scriptComboBox);

            JLabel payloadsPreviewLabel = new JLabel(PAYLOADS_PREVIEW_FIELD_LABEL);
            payloadsPreviewLabel.setLabelFor(getPayloadsPreviewTextArea());

            JScrollPane payloadsPreviewScrollPane = new JScrollPane(getPayloadsPreviewTextArea());

            layout.setHorizontalGroup(
                    layout.createSequentialGroup()
                            .addGroup(
                                    layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                                            .addComponent(scriptLabel)
                                            .addComponent(payloadsPreviewLabel))
                            .addGroup(
                                    layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                            .addComponent(scriptComboBox)
                                            .addGroup(
                                                    layout.createSequentialGroup()
                                                            .addComponent(
                                                                    getPayloadsPreviewGenerateButton())
                                                            .addComponent(getSaveButton()))
                                            .addComponent(payloadsPreviewScrollPane)));

            layout.setVerticalGroup(
                    layout.createSequentialGroup()
                            .addGroup(
                                    layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                            .addComponent(scriptLabel)
                                            .addComponent(scriptComboBox))
                            .addGroup(
                                    layout.createParallelGroup()
                                            .addComponent(getPayloadsPreviewGenerateButton())
                                            .addComponent(getSaveButton()))
                            .addGroup(
                                    layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                            .addComponent(payloadsPreviewLabel)
                                            .addComponent(payloadsPreviewScrollPane)));
        }

        private JButton getPayloadsPreviewGenerateButton() {
            if (payloadsPreviewGenerateButton == null) {
                payloadsPreviewGenerateButton = new JButton(PAYLOADS_PREVIEW_GENERATE_FIELD_LABEL);
                payloadsPreviewGenerateButton.setEnabled(false);

                payloadsPreviewGenerateButton.addActionListener(
                        e -> updatePayloadsPreviewTextArea());
            }
            return payloadsPreviewGenerateButton;
        }

        private JTextArea getPayloadsPreviewTextArea() {
            if (payloadsPreviewTextArea == null) {
                payloadsPreviewTextArea = new JTextArea(15, 10);
                payloadsPreviewTextArea.setEditable(false);
                payloadsPreviewTextArea.setFont(FontUtils.getFont("Monospaced"));
            }
            return payloadsPreviewTextArea;
        }

        private void updatePayloadsPreviewTextArea() {
            ScriptStringPayloadGeneratorAdapter scriptPayloadGenerator = getPayloadGenerator();
            if (scriptPayloadGenerator == null) {
                return;
            }
            StringBuilder contents = new StringBuilder();
            try {
                try (ResettableAutoCloseableIterator<DefaultPayload> itPayloads =
                        scriptPayloadGenerator.iterator()) {
                    for (int i = 0; i < MAX_NUMBER_PAYLOADS_PREVIEW && itPayloads.hasNext(); i++) {
                        if (contents.length() > 0) {
                            contents.append('\n');
                        }
                        contents.append(itPayloads.next().getValue());
                    }
                    itPayloads.reset();
                }
                getPayloadsPreviewTextArea().setEnabled(true);
            } catch (Exception ignore) {
                contents.setLength(0);
                contents.append(
                        Constant.messages.getString(
                                "fuzz.payloads.generator.script.payloadsPreview.error"));
                getPayloadsPreviewTextArea().setEnabled(false);
            }
            getPayloadsPreviewTextArea().setText(contents.toString());
            getPayloadsPreviewTextArea().setCaretPosition(0);
        }

        @Override
        public void init(MessageLocation messageLocation) {
            int selectedItem = scriptComboBox.getSelectedIndex();
            if (selectedItem != -1) {
                updatePreviewFor(scriptComboBox.getItemAt(selectedItem));
            }
        }

        private void updatePreviewFor(ScriptUIEntry entry) {
            setPreviewAndSaveButtonsEnabled(!entry.getScriptWrapper().isError());
            getPayloadsPreviewTextArea().setText("");
        }

        private void setPreviewAndSaveButtonsEnabled(boolean enabled) {
            getPayloadsPreviewGenerateButton().setEnabled(enabled);
            getSaveButton().setEnabled(enabled);
        }

        @Override
        public JPanel getComponent() {
            return fieldsPanel;
        }

        @Override
        public void setPayloadGeneratorUI(
                ScriptStringPayloadGeneratorAdapterUI payloadGeneratorUI) {
            scriptComboBox.setSelectedItem(
                    new PayloadGeneratorScriptUIEntry(payloadGeneratorUI.getScriptWrapper()));
            PayloadGeneratorScriptUIEntry scriptUIEntry =
                    (PayloadGeneratorScriptUIEntry) scriptComboBox.getSelectedItem();
            if (scriptUIEntry != null) {
                scriptUIEntry.setScriptPayloadGenerator(
                        payloadGeneratorUI.getScriptStringPayloadGenerator());
            }
            setPreviewAndSaveButtonsEnabled(true);
        }

        @Override
        public ScriptStringPayloadGeneratorAdapterUI getPayloadGeneratorUI() {
            PayloadGeneratorScriptUIEntry scriptUIEntry =
                    ((PayloadGeneratorScriptUIEntry) scriptComboBox.getSelectedItem());
            ScriptWrapper scriptWrapper = scriptUIEntry.getScriptWrapper();
            return new ScriptStringPayloadGeneratorAdapterUI(
                    scriptWrapper, scriptUIEntry.getScriptPayloadGenerator());
        }

        @Override
        protected ScriptStringPayloadGeneratorAdapter getPayloadGenerator() {
            if (!validateScriptImpl()) {
                return null;
            }
            PayloadGeneratorScriptUIEntry scriptUIEntry =
                    ((PayloadGeneratorScriptUIEntry) scriptComboBox.getSelectedItem());
            ScriptWrapper scriptWrapper = scriptUIEntry.getScriptWrapper();
            return new ScriptStringPayloadGeneratorAdapter(
                    scriptWrapper, scriptUIEntry.getScriptPayloadGenerator());
        }

        @Override
        public void clear() {
            for (int i = 0; i < scriptComboBox.getItemCount(); i++) {
                PayloadGeneratorScriptUIEntry scriptUIEntry =
                        ((PayloadGeneratorScriptUIEntry) scriptComboBox.getItemAt(i));
                scriptUIEntry.setScriptPayloadGenerator(null);
            }
            getPayloadsPreviewTextArea().setText("");
            setPreviewAndSaveButtonsEnabled(false);
        }

        @Override
        public boolean validate() {
            if (scriptComboBox.getSelectedIndex() == -1) {
                JOptionPane.showMessageDialog(
                        null,
                        Constant.messages.getString(
                                "fuzz.payloads.generator.script.warnNoScript.message"),
                        Constant.messages.getString(
                                "fuzz.payloads.generator.script.warnNoScript.title"),
                        JOptionPane.INFORMATION_MESSAGE);
                scriptComboBox.requestFocusInWindow();
                return false;
            }

            boolean valid = validateScriptImpl();
            if (!valid) {
                return false;
            }

            PayloadGeneratorScriptUIEntry scriptUIEntry =
                    ((PayloadGeneratorScriptUIEntry) scriptComboBox.getSelectedItem());
            ScriptWrapper scriptWrapper = scriptUIEntry.getScriptWrapper();
            ScriptStringPayloadGenerator scriptPayloadGenerator =
                    scriptUIEntry.getScriptPayloadGenerator();
            try {
                scriptPayloadGenerator.getNumberOfPayloads();
            } catch (Exception e) {
                handleScriptExceptionImpl(scriptWrapper, e);
                LOGGER.warn(
                        "Failed to obtain number of payloads from script '{}': {}",
                        scriptWrapper.getName(),
                        e.getMessage());
                JOptionPane.showMessageDialog(
                        null,
                        Constant.messages.getString(
                                "fuzz.payloads.generator.script.warnNoNumberOfpayloads.message"),
                        Constant.messages.getString(
                                "fuzz.payloads.generator.script.warnNoNumberOfpayloads.title"),
                        JOptionPane.INFORMATION_MESSAGE);
            }

            return true;
        }

        private boolean validateScriptImpl() {
            PayloadGeneratorScriptUIEntry scriptUIEntry =
                    ((PayloadGeneratorScriptUIEntry) scriptComboBox.getSelectedItem());
            ScriptWrapper scriptWrapper = scriptUIEntry.getScriptWrapper();
            ScriptStringPayloadGenerator scriptPayloadGenerator =
                    scriptUIEntry.getScriptPayloadGenerator();
            if (scriptPayloadGenerator == null) {
                try {
                    scriptPayloadGenerator = initialiseImpl(scriptWrapper);
                    if (scriptPayloadGenerator == null) {
                        JOptionPane.showMessageDialog(
                                null,
                                Constant.messages.getString(
                                        "fuzz.payloads.generator.script.warnNoInterface.message"),
                                Constant.messages.getString(
                                        "fuzz.payloads.generator.script.warnNoInterface.title"),
                                JOptionPane.INFORMATION_MESSAGE);
                        handleScriptExceptionImpl(
                                scriptWrapper,
                                Constant.messages.getString(
                                        "fuzz.payloads.generator.script.warnNoInterface.message"));
                        setPreviewAndSaveButtonsEnabled(false);
                        return false;
                    }
                } catch (Exception e) {
                    handleScriptExceptionImpl(scriptWrapper, e);
                    JOptionPane.showMessageDialog(
                            null,
                            Constant.messages.getString(
                                    "fuzz.payloads.generator.script.warnNoInterface.message"),
                            Constant.messages.getString(
                                    "fuzz.payloads.generator.script.warnNoInterface.title"),
                            JOptionPane.INFORMATION_MESSAGE);
                    LOGGER.warn(
                            "Failed to initialise '{}': {}",
                            scriptWrapper.getName(),
                            e.getMessage());
                    setPreviewAndSaveButtonsEnabled(false);
                    return false;
                }
                scriptUIEntry.setScriptPayloadGenerator(scriptPayloadGenerator);
            }
            return true;
        }

        private static class PayloadGeneratorScriptUIEntry extends ScriptUIEntry {

            private ScriptStringPayloadGenerator scriptPayloadGenerator;

            public PayloadGeneratorScriptUIEntry(ScriptWrapper scriptWrapper) {
                super(scriptWrapper);
            }

            public ScriptStringPayloadGenerator getScriptPayloadGenerator() {
                return scriptPayloadGenerator;
            }

            public void setScriptPayloadGenerator(
                    ScriptStringPayloadGenerator scriptPayloadGenerator) {
                this.scriptPayloadGenerator = scriptPayloadGenerator;
            }
        }
    }

    private static ScriptStringPayloadGenerator initialiseImpl(ScriptWrapper scriptWrapper)
            throws Exception {
        ExtensionScript extensionScript =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionScript.class);
        if (extensionScript != null) {
            return extensionScript.getInterface(scriptWrapper, ScriptStringPayloadGenerator.class);
        }
        return null;
    }

    private static void handleScriptExceptionImpl(ScriptWrapper scriptWrapper, Exception cause) {
        ExtensionScript extensionScript =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionScript.class);
        if (extensionScript != null) {
            extensionScript.setError(scriptWrapper, cause);
            extensionScript.setEnabled(scriptWrapper, false);
        }
    }

    private static void handleScriptExceptionImpl(ScriptWrapper scriptWrapper, String error) {
        ExtensionScript extensionScript =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionScript.class);
        if (extensionScript != null) {
            extensionScript.setError(scriptWrapper, error);
            extensionScript.setEnabled(scriptWrapper, false);
        }
    }
}
