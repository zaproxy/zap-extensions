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
package org.zaproxy.zap.extension.fuzz.payloads.ui.processors;

import java.util.List;

import javax.swing.GroupLayout;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.zaproxy.zap.extension.fuzz.payloads.DefaultPayload;
import org.zaproxy.zap.extension.fuzz.payloads.processor.ScriptStringPayloadProcessor;
import org.zaproxy.zap.extension.fuzz.payloads.processor.ScriptStringPayloadProcessorAdapter;
import org.zaproxy.zap.extension.fuzz.payloads.ui.processors.ScriptStringPayloadProcessorAdapterUIHandler.ScriptStringPayloadProcessorAdapterUI;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.utils.SortedComboBoxModel;

public class ScriptStringPayloadProcessorAdapterUIHandler
        implements
        PayloadProcessorUIHandler<DefaultPayload, ScriptStringPayloadProcessorAdapter, ScriptStringPayloadProcessorAdapterUI> {

    private static final Logger LOGGER = Logger.getLogger(ScriptStringPayloadProcessorAdapterUIHandler.class);

    private static final String PROCESSOR_NAME = Constant.messages.getString("fuzz.payload.processor.script.name");

    private final ExtensionScript extensionScript;

    public ScriptStringPayloadProcessorAdapterUIHandler(ExtensionScript extensionScript) {
        this.extensionScript = extensionScript;
    }

    @Override
    public String getName() {
        return PROCESSOR_NAME;
    }

    @Override
    public Class<ScriptStringPayloadProcessorAdapterUI> getPayloadProcessorUIClass() {
        return ScriptStringPayloadProcessorAdapterUI.class;
    }

    @Override
    public Class<ScriptStringPayloadProcessorAdapterUIPanel> getPayloadProcessorUIPanelClass() {
        return ScriptStringPayloadProcessorAdapterUIPanel.class;
    }

    @Override
    public ScriptStringPayloadProcessorAdapterUIPanel createPanel() {
        return new ScriptStringPayloadProcessorAdapterUIPanel(
                extensionScript.getScripts(ScriptStringPayloadProcessor.TYPE_NAME));
    }

    public static class ScriptStringPayloadProcessorAdapterUI implements
            PayloadProcessorUI<DefaultPayload, ScriptStringPayloadProcessorAdapter> {

        private final ScriptWrapper scriptWrapper;

        public ScriptStringPayloadProcessorAdapterUI(ScriptWrapper scriptWrapper) {
            this.scriptWrapper = scriptWrapper;
        }

        public ScriptWrapper getScriptWrapper() {
            return scriptWrapper;
        }

        @Override
        public Class<ScriptStringPayloadProcessorAdapter> getPayloadProcessorClass() {
            return ScriptStringPayloadProcessorAdapter.class;
        }

        @Override
        public String getName() {
            return PROCESSOR_NAME;
        }

        @Override
        public boolean isMutable() {
            return true;
        }

        @Override
        public String getDescription() {
            return scriptWrapper.getName();
        }

        @Override
        public ScriptStringPayloadProcessorAdapter getPayloadProcessor() {
            return new ScriptStringPayloadProcessorAdapter(scriptWrapper);
        }

        @Override
        public ScriptStringPayloadProcessorAdapterUI copy() {
            return this;
        }

    }

    public static class ScriptStringPayloadProcessorAdapterUIPanel
            extends
            AbstractProcessorUIPanel<DefaultPayload, ScriptStringPayloadProcessorAdapter, ScriptStringPayloadProcessorAdapterUI> {

        private static final String SCRIPT_FIELD_LABEL = Constant.messages.getString("fuzz.payload.processor.script.script.label");

        private final JPanel fieldsPanel;
        private final JComboBox<ScriptUIEntry> scriptComboBox;

        public ScriptStringPayloadProcessorAdapterUIPanel(List<ScriptWrapper> scriptWrappers) {
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
        public JPanel getComponent() {
            return fieldsPanel;
        }

        @Override
        public void setPayloadProcessorUI(ScriptStringPayloadProcessorAdapterUI payloadProcessorUI) {
            scriptComboBox.setSelectedItem(new ScriptUIEntry(payloadProcessorUI.getScriptWrapper()));
        }

        @Override
        public ScriptStringPayloadProcessorAdapterUI getPayloadProcessorUI() {
            return new ScriptStringPayloadProcessorAdapterUI(
                    ((ScriptUIEntry) scriptComboBox.getSelectedItem()).getScriptWrapper());
        }

        @Override
        public boolean validate() {
            if (scriptComboBox.getSelectedIndex() == -1) {
                JOptionPane.showMessageDialog(
                        null,
                        Constant.messages.getString("fuzz.payload.processor.script.warnNoScript.message"),
                        Constant.messages.getString("fuzz.payload.processor.script.warnNoScript.title"),
                        JOptionPane.INFORMATION_MESSAGE);
                scriptComboBox.requestFocusInWindow();
                return false;
            }

            ScriptUIEntry scriptUIEntry = ((ScriptUIEntry) scriptComboBox.getSelectedItem());
            ScriptWrapper scriptWrapper = scriptUIEntry.getScriptWrapper();
            try {
                ScriptStringPayloadProcessor scriptPayloadGenerator = initialiseImpl(scriptWrapper);
                if (scriptPayloadGenerator == null) {
                    JOptionPane.showMessageDialog(
                            null,
                            Constant.messages.getString("fuzz.payload.processor.script.warnNoInterface.message"),
                            Constant.messages.getString("fuzz.payload.processor.script.warnNoInterface.title"),
                            JOptionPane.INFORMATION_MESSAGE);
                    handleScriptExceptionImpl(
                            scriptWrapper,
                            Constant.messages.getString("fuzz.payload.processor.script.warnNoInterface.message"));
                    return false;
                }
            } catch (Exception e) {
                handleScriptExceptionImpl(scriptWrapper, e);
                JOptionPane.showMessageDialog(
                        null,
                        Constant.messages.getString("fuzz.payload.processor.script.warnNoInterface.message"),
                        Constant.messages.getString("fuzz.payload.processor.script.warnNoInterface.title"),
                        JOptionPane.INFORMATION_MESSAGE);
                LOGGER.warn("Failed to validate '" + scriptWrapper.getName() + "': " + e.getMessage());
                return false;
            }
            return true;
        }

        @Override
        public ScriptStringPayloadProcessorAdapter getPayloadProcessor() {
            if (!validate()) {
                return null;
            }
            return new ScriptStringPayloadProcessorAdapter(
                    ((ScriptUIEntry) scriptComboBox.getSelectedItem()).getScriptWrapper());
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

    private static ScriptStringPayloadProcessor initialiseImpl(ScriptWrapper scriptWrapper) throws Exception {
        ExtensionScript extensionScript = Control.getSingleton().getExtensionLoader().getExtension(ExtensionScript.class);
        if (extensionScript != null) {
            return extensionScript.getInterface(scriptWrapper, ScriptStringPayloadProcessor.class);
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

    private static void handleScriptExceptionImpl(ScriptWrapper scriptWrapper, String error) {
        ExtensionScript extensionScript = Control.getSingleton().getExtensionLoader().getExtension(ExtensionScript.class);
        if (extensionScript != null) {
            extensionScript.setError(scriptWrapper, error);
            extensionScript.setEnabled(scriptWrapper, false);
        }
    }
}
