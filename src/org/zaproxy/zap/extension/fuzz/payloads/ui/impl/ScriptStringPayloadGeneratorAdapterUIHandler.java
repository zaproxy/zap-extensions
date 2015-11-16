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

import java.util.List;

import javax.swing.GroupLayout;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.zaproxy.zap.extension.fuzz.payloads.StringPayload;
import org.zaproxy.zap.extension.fuzz.payloads.generator.PayloadGenerator;
import org.zaproxy.zap.extension.fuzz.payloads.generator.ScriptStringPayloadGenerator;
import org.zaproxy.zap.extension.fuzz.payloads.generator.ScriptStringPayloadGeneratorAdapter;
import org.zaproxy.zap.extension.fuzz.payloads.ui.PayloadGeneratorUI;
import org.zaproxy.zap.extension.fuzz.payloads.ui.PayloadGeneratorUIHandler;
import org.zaproxy.zap.extension.fuzz.payloads.ui.PayloadGeneratorUIPanel;
import org.zaproxy.zap.extension.fuzz.payloads.ui.impl.ScriptStringPayloadGeneratorAdapterUIHandler.ScriptStringPayloadGeneratorAdapterUI;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.model.MessageLocation;
import org.zaproxy.zap.utils.SortedComboBoxModel;

public class ScriptStringPayloadGeneratorAdapterUIHandler
        implements
        PayloadGeneratorUIHandler<String, StringPayload, ScriptStringPayloadGeneratorAdapter, ScriptStringPayloadGeneratorAdapterUI> {

    private static final Logger LOGGER = Logger.getLogger(ScriptStringPayloadGeneratorAdapterUIHandler.class);

    private static final String PAYLOAD_GENERATOR_NAME = Constant.messages.getString("fuzz.payloads.generator.script.name");

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

    public static class ScriptStringPayloadGeneratorAdapterUI implements
            PayloadGeneratorUI<String, StringPayload, ScriptStringPayloadGeneratorAdapter> {

        private final ScriptWrapper scriptWrapper;
        private ScriptStringPayloadGenerator scriptPayloadGenerator;

        public ScriptStringPayloadGeneratorAdapterUI(ScriptWrapper scriptWrapper, ScriptStringPayloadGenerator scriptPayloadGenerator) {
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
                LOGGER.warn("Failed to obtain number of payloads from script '" + scriptWrapper.getName() + "':", e);
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
            implements
            PayloadGeneratorUIPanel<String, StringPayload, ScriptStringPayloadGeneratorAdapter, ScriptStringPayloadGeneratorAdapterUI> {

        private static final String SCRIPT_FIELD_LABEL = Constant.messages.getString("fuzz.payloads.generator.script.script.label");

        private JPanel fieldsPanel;
        private final JComboBox<ScriptUIEntry> scriptComboBox;

        public ScriptStringPayloadGeneratorAdapterUIPanel(List<ScriptWrapper> scriptWrappers) {
            scriptComboBox = new JComboBox<>(new SortedComboBoxModel<ScriptUIEntry>());
            for (ScriptWrapper scriptWrapper : scriptWrappers) {
                if (scriptWrapper.isEnabled()) {
                    scriptComboBox.addItem(new ScriptUIEntry(scriptWrapper));
                }
            }

            fieldsPanel = new JPanel();

            GroupLayout layout = new GroupLayout(fieldsPanel);
            fieldsPanel.setLayout(layout);
            layout.setAutoCreateGaps(true);

            JLabel scriptLabel = new JLabel(SCRIPT_FIELD_LABEL);
            scriptLabel.setLabelFor(scriptComboBox);

            layout.setHorizontalGroup(layout.createSequentialGroup().addComponent(scriptLabel).addComponent(scriptComboBox));

            layout.setVerticalGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(scriptLabel)
                    .addComponent(scriptComboBox));
        }

        @Override
        public void init(MessageLocation messageLocation) {
        }

        @Override
        public JPanel getComponent() {
            return fieldsPanel;
        }

        @Override
        public void setPayloadGeneratorUI(ScriptStringPayloadGeneratorAdapterUI payloadGeneratorUI) {
            scriptComboBox.setSelectedItem(new ScriptUIEntry(payloadGeneratorUI.getScriptWrapper()));
            ScriptUIEntry scriptUIEntry = (ScriptUIEntry) scriptComboBox.getSelectedItem();
            if (scriptUIEntry != null) {
                scriptUIEntry.setScriptPayloadGenerator(payloadGeneratorUI.getScriptStringPayloadGenerator());
            }
        }

        @Override
        public ScriptStringPayloadGeneratorAdapterUI getPayloadGeneratorUI() {
            ScriptUIEntry scriptUIEntry = ((ScriptUIEntry) scriptComboBox.getSelectedItem());
            ScriptWrapper scriptWrapper =  scriptUIEntry.getScriptWrapper();
            return new ScriptStringPayloadGeneratorAdapterUI(scriptWrapper, scriptUIEntry.getScriptPayloadGenerator());
        }

        @Override
        public void clear() {
            scriptComboBox.setSelectedIndex(-1);
            for (int i = 0; i < scriptComboBox.getItemCount(); i++) {
                scriptComboBox.getItemAt(i).setScriptPayloadGenerator(null);
            }
        }

        @Override
        public boolean validate() {
            if (scriptComboBox.getSelectedIndex() == -1) {
                JOptionPane.showMessageDialog(
                        null,
                        Constant.messages.getString("fuzz.payloads.generator.script.warnNoScript.message"),
                        Constant.messages.getString("fuzz.payloads.generator.script.warnNoScript.title"),
                        JOptionPane.INFORMATION_MESSAGE);
                scriptComboBox.requestFocusInWindow();
                return false;
            }

            ScriptUIEntry scriptUIEntry = ((ScriptUIEntry) scriptComboBox.getSelectedItem());
            ScriptWrapper scriptWrapper =  scriptUIEntry.getScriptWrapper();
            ScriptStringPayloadGenerator scriptPayloadGenerator = scriptUIEntry.getScriptPayloadGenerator();
            if (scriptPayloadGenerator == null) {
                try {
                    scriptPayloadGenerator = initialiseImpl(scriptWrapper);
                    if (scriptPayloadGenerator == null) {
                        JOptionPane.showMessageDialog(
                                null,
                                Constant.messages.getString("fuzz.payloads.generator.script.warnNoInterface.message"),
                                Constant.messages.getString("fuzz.payloads.generator.script.warnNoInterface.title"),
                                JOptionPane.INFORMATION_MESSAGE);
                        return false;
                    }
                } catch (Exception e) {
                    handleScriptExceptionImpl(scriptWrapper, e);
                    JOptionPane.showMessageDialog(
                            null,
                            Constant.messages.getString("fuzz.payloads.generator.script.warnNoInterface.message"),
                            Constant.messages.getString("fuzz.payloads.generator.script.warnNoInterface.title"),
                            JOptionPane.INFORMATION_MESSAGE);
                    LOGGER.warn("Failed to initialise '" + scriptWrapper.getName() + "': " + e.getMessage());
                    return false;
                }
                scriptUIEntry.setScriptPayloadGenerator(scriptPayloadGenerator);
            }

            try {
                scriptPayloadGenerator.getNumberOfPayloads();
            } catch (Exception e) {
                handleScriptExceptionImpl(scriptWrapper, e);
                LOGGER.warn("Failed to obtain number of payloads from script '" + scriptWrapper.getName() + "': " + e.getMessage());
                JOptionPane.showMessageDialog(
                        null,
                        Constant.messages.getString("fuzz.payloads.generator.script.warnNoNumberOfpayloads.message"),
                        Constant.messages.getString("fuzz.payloads.generator.script.warnNoNumberOfpayloads.title"),
                        JOptionPane.INFORMATION_MESSAGE);
            }

            return true;
        }

        @Override
        public String getHelpTarget() {
            // THC add help page...
            return null;
        }

        private static class ScriptUIEntry implements Comparable<ScriptUIEntry> {

            private final ScriptWrapper scriptWrapper;
            private final String scriptName;
            private ScriptStringPayloadGenerator scriptPayloadGenerator;

            public ScriptUIEntry(ScriptWrapper scriptWrapper) {
                this.scriptWrapper = scriptWrapper;
                this.scriptName = scriptWrapper.getName();
                if (scriptName == null) {
                    throw new IllegalArgumentException("Script must have a name.");
                }
            }

            public ScriptStringPayloadGenerator getScriptPayloadGenerator() {
                return scriptPayloadGenerator;
            }

            public void setScriptPayloadGenerator(ScriptStringPayloadGenerator scriptPayloadGenerator) {
                this.scriptPayloadGenerator = scriptPayloadGenerator;
            }

            public ScriptWrapper getScriptWrapper() {
                return scriptWrapper;
            }

            @Override
            public String toString() {
                return scriptName;
            }

            @Override
            public int hashCode() {
                final int prime = 31;
                int result = 1;
                result = prime * result + ((scriptName == null) ? 0 : scriptName.hashCode());
                return result;
            }

            @Override
            public boolean equals(Object obj) {
                if (this == obj) {
                    return true;
                }
                if (obj == null) {
                    return false;
                }
                if (getClass() != obj.getClass()) {
                    return false;
                }
                ScriptUIEntry other = (ScriptUIEntry) obj;
                if (scriptName == null) {
                    if (other.scriptName != null) {
                        return false;
                    }
                } else if (!scriptName.equals(other.scriptName)) {
                    return false;
                }
                return true;
            }

            @Override
            public int compareTo(ScriptUIEntry other) {
                if (other == null) {
                    return 1;
                }
                return scriptName.compareTo(other.scriptName);
            }

        }
    }

    private static ScriptStringPayloadGenerator initialiseImpl(ScriptWrapper scriptWrapper) throws Exception {
        ExtensionScript extensionScript = Control.getSingleton().getExtensionLoader().getExtension(ExtensionScript.class);
        if (extensionScript != null) {
            return extensionScript.getInterface(scriptWrapper, ScriptStringPayloadGenerator.class);
        }
        return null;
    }

    private static void handleScriptExceptionImpl(ScriptWrapper scriptWrapper, Exception cause) {
        ExtensionScript extensionScript = Control.getSingleton().getExtensionLoader().getExtension(ExtensionScript.class);
        if (extensionScript != null) {
            extensionScript.setError(scriptWrapper, cause);
            extensionScript.setEnabled(scriptWrapper, false);
        }
    }
}
