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

import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.fuzz.payloads.StringPayload;
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

        public ScriptStringPayloadGeneratorAdapterUI(ScriptWrapper scriptWrapper) {
            this.scriptWrapper = scriptWrapper;
        }

        public ScriptWrapper getScriptWrapper() {
            return scriptWrapper;
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
            return 0;
        }

        @Override
        public ScriptStringPayloadGeneratorAdapter getPayloadGenerator() {
            return new ScriptStringPayloadGeneratorAdapter(scriptWrapper);
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
        }

        @Override
        public ScriptStringPayloadGeneratorAdapterUI getPayloadGeneratorUI() {
            return new ScriptStringPayloadGeneratorAdapterUI(
                    ((ScriptUIEntry) scriptComboBox.getSelectedItem()).getScriptWrapper());
        }

        @Override
        public void clear() {
            scriptComboBox.setSelectedIndex(-1);
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

            public ScriptUIEntry(ScriptWrapper scriptWrapper) {
                this.scriptWrapper = scriptWrapper;
                this.scriptName = scriptWrapper.getName();
                if (scriptName == null) {
                    throw new IllegalArgumentException("Script must have a name.");
                }
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
}
