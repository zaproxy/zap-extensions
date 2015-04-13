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
package org.zaproxy.zap.extension.fuzz.httpfuzzer.processors;

import java.util.List;

import javax.swing.GroupLayout;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.AbstractHttpFuzzerMessageProcessorUIPanel;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.HttpFuzzerMessageProcessorUI;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.HttpFuzzerMessageProcessorUIHandler;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.processors.FuzzerHttpMessageScriptProcessorAdapterUIHandler.FuzzerHttpMessageScriptProcessorAdapterUI;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.utils.SortedComboBoxModel;

public class FuzzerHttpMessageScriptProcessorAdapterUIHandler implements
        HttpFuzzerMessageProcessorUIHandler<FuzzerHttpMessageScriptProcessorAdapter, FuzzerHttpMessageScriptProcessorAdapterUI> {

    private static final String PROCESSOR_NAME = Constant.messages.getString("fuzz.httpfuzzer.processor.scriptProcessor.name");

    private final ExtensionScript extensionScript;

    public FuzzerHttpMessageScriptProcessorAdapterUIHandler(ExtensionScript extensionScript) {
        this.extensionScript = extensionScript;
    }

    @Override
    public boolean isEnabled(HttpMessage message) {
        return true;
    }

    @Override
    public boolean isDefault() {
        return false;
    }

    @Override
    public FuzzerHttpMessageScriptProcessorAdapterUI createDefault() {
        return null;
    }

    @Override
    public String getName() {
        return PROCESSOR_NAME;
    }

    @Override
    public Class<HttpMessage> getMessageType() {
        return HttpMessage.class;
    }

    @Override
    public Class<FuzzerHttpMessageScriptProcessorAdapter> getFuzzerMessageProcessorType() {
        return FuzzerHttpMessageScriptProcessorAdapter.class;
    }

    @Override
    public Class<FuzzerHttpMessageScriptProcessorAdapterUI> getFuzzerMessageProcessorUIType() {
        return FuzzerHttpMessageScriptProcessorAdapterUI.class;
    }

    @Override
    public FuzzerHttpMessageScriptProcessorAdapterUIPanel createPanel() {
        return new FuzzerHttpMessageScriptProcessorAdapterUIPanel(
                extensionScript.getScripts(HttpFuzzerProcessorScript.TYPE_NAME));
    }

    public static class FuzzerHttpMessageScriptProcessorAdapterUI implements
            HttpFuzzerMessageProcessorUI<FuzzerHttpMessageScriptProcessorAdapter> {

        private final ScriptWrapper scriptWrapper;

        public FuzzerHttpMessageScriptProcessorAdapterUI(ScriptWrapper scriptWrapper) {
            this.scriptWrapper = scriptWrapper;
        }

        public ScriptWrapper getScriptWrapper() {
            return scriptWrapper;
        }

        @Override
        public boolean isMutable() {
            return true;
        }

        @Override
        public String getName() {
            return PROCESSOR_NAME;
        }

        @Override
        public String getDescription() {
            return scriptWrapper.getName();
        }

        @Override
        public FuzzerHttpMessageScriptProcessorAdapter getFuzzerMessageProcessor() {
            return new FuzzerHttpMessageScriptProcessorAdapter(scriptWrapper);
        }

        @Override
        public FuzzerHttpMessageScriptProcessorAdapterUI copy() {
            return new FuzzerHttpMessageScriptProcessorAdapterUI(scriptWrapper);
        }
    }

    public static class FuzzerHttpMessageScriptProcessorAdapterUIPanel
            extends
            AbstractHttpFuzzerMessageProcessorUIPanel<FuzzerHttpMessageScriptProcessorAdapter, FuzzerHttpMessageScriptProcessorAdapterUI> {

        private static final String SCRIPT_FIELD_LABEL = Constant.messages.getString("fuzz.httpfuzzer.processor.scriptProcessor.panel.script.label");

        private final JPanel fieldsPanel;
        private final JComboBox<ScriptUIEntry> scriptComboBox;

        public FuzzerHttpMessageScriptProcessorAdapterUIPanel(List<ScriptWrapper> scriptWrappers) {
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
        public void setFuzzerMessageProcessorUI(FuzzerHttpMessageScriptProcessorAdapterUI payloadProcessorUI) {
            scriptComboBox.setSelectedItem(payloadProcessorUI.getScriptWrapper());
        }

        @Override
        public FuzzerHttpMessageScriptProcessorAdapterUI getFuzzerMessageProcessorUI() {
            return new FuzzerHttpMessageScriptProcessorAdapterUI(
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
                        Constant.messages.getString("fuzz.httpfuzzer.processor.scriptProcessor.panel.warnNoScript.message"),
                        Constant.messages.getString("fuzz.httpfuzzer.processor.scriptProcessor.panel.warnNoScript.title"),
                        JOptionPane.INFORMATION_MESSAGE);
                scriptComboBox.requestFocusInWindow();
                return false;
            }
            return true;
        }

        @Override
        public String getHelpTarget() {
            // THC add help target...
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
