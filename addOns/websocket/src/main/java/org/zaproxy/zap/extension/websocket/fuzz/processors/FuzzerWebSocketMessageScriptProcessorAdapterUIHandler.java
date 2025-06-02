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
package org.zaproxy.zap.extension.websocket.fuzz.processors;

import java.util.List;
import javax.swing.GroupLayout;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.websocket.WebSocketMessageDTO;
import org.zaproxy.zap.extension.websocket.fuzz.AbstractWebSocketFuzzerMessageProcessorUIPanel;
import org.zaproxy.zap.extension.websocket.fuzz.WebSocketFuzzerMessageProcessorUI;
import org.zaproxy.zap.extension.websocket.fuzz.WebSocketFuzzerMessageProcessorUIHandler;
import org.zaproxy.zap.extension.websocket.fuzz.processors.FuzzerWebSocketMessageScriptProcessorAdapterUIHandler.FuzzerWebSocketMessageScriptProcessorAdapterUI;
import org.zaproxy.zap.utils.SortedComboBoxModel;

public class FuzzerWebSocketMessageScriptProcessorAdapterUIHandler
        implements WebSocketFuzzerMessageProcessorUIHandler<
                FuzzerWebSocketMessageScriptProcessorAdapter,
                FuzzerWebSocketMessageScriptProcessorAdapterUI> {

    private static final String PROCESSOR_NAME =
            Constant.messages.getString("websocket.fuzzer.processor.scriptProcessor.name");

    private final ExtensionScript extensionScript;

    public FuzzerWebSocketMessageScriptProcessorAdapterUIHandler(ExtensionScript extensionScript) {
        this.extensionScript = extensionScript;
    }

    @Override
    public boolean isEnabled(WebSocketMessageDTO message) {
        return true;
    }

    @Override
    public boolean isDefault() {
        return false;
    }

    @Override
    public FuzzerWebSocketMessageScriptProcessorAdapterUI createDefault() {
        return null;
    }

    @Override
    public String getName() {
        return PROCESSOR_NAME;
    }

    @Override
    public Class<WebSocketMessageDTO> getMessageType() {
        return WebSocketMessageDTO.class;
    }

    @Override
    public Class<FuzzerWebSocketMessageScriptProcessorAdapter> getFuzzerMessageProcessorType() {
        return FuzzerWebSocketMessageScriptProcessorAdapter.class;
    }

    @Override
    public Class<FuzzerWebSocketMessageScriptProcessorAdapterUI> getFuzzerMessageProcessorUIType() {
        return FuzzerWebSocketMessageScriptProcessorAdapterUI.class;
    }

    @Override
    public FuzzerWebSocketMessageScriptProcessorAdapterUIPanel createPanel() {
        return new FuzzerWebSocketMessageScriptProcessorAdapterUIPanel(
                extensionScript.getScripts(WebSocketFuzzerProcessorScript.TYPE_NAME));
    }

    public static class FuzzerWebSocketMessageScriptProcessorAdapterUI
            implements WebSocketFuzzerMessageProcessorUI<
                    FuzzerWebSocketMessageScriptProcessorAdapter> {

        private final ScriptWrapper scriptWrapper;

        public FuzzerWebSocketMessageScriptProcessorAdapterUI(ScriptWrapper scriptWrapper) {
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
        public FuzzerWebSocketMessageScriptProcessorAdapter getFuzzerMessageProcessor() {
            return new FuzzerWebSocketMessageScriptProcessorAdapter(scriptWrapper);
        }

        @Override
        public FuzzerWebSocketMessageScriptProcessorAdapterUI copy() {
            return new FuzzerWebSocketMessageScriptProcessorAdapterUI(scriptWrapper);
        }
    }

    public static class FuzzerWebSocketMessageScriptProcessorAdapterUIPanel
            extends AbstractWebSocketFuzzerMessageProcessorUIPanel<
                    FuzzerWebSocketMessageScriptProcessorAdapter,
                    FuzzerWebSocketMessageScriptProcessorAdapterUI> {

        private static final String SCRIPT_FIELD_LABEL =
                Constant.messages.getString(
                        "websocket.fuzzer.processor.scriptProcessor.panel.script.label");

        private final JPanel fieldsPanel;
        private final JComboBox<ScriptUIEntry> scriptComboBox;

        public FuzzerWebSocketMessageScriptProcessorAdapterUIPanel(
                List<ScriptWrapper> scriptWrappers) {
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

            layout.setHorizontalGroup(
                    layout.createSequentialGroup()
                            .addComponent(scriptLabel)
                            .addComponent(scriptComboBox));

            layout.setVerticalGroup(
                    layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                            .addComponent(scriptLabel)
                            .addComponent(scriptComboBox));
        }

        @Override
        public JPanel getComponent() {
            return fieldsPanel;
        }

        @Override
        public void setFuzzerMessageProcessorUI(
                FuzzerWebSocketMessageScriptProcessorAdapterUI payloadProcessorUI) {
            scriptComboBox.setSelectedItem(
                    new ScriptUIEntry(payloadProcessorUI.getScriptWrapper()));
        }

        @Override
        public FuzzerWebSocketMessageScriptProcessorAdapterUI getFuzzerMessageProcessorUI() {
            return new FuzzerWebSocketMessageScriptProcessorAdapterUI(
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
                        Constant.messages.getString(
                                "websocket.fuzzer.processor.scriptProcessor.panel.warnNoScript.message"),
                        Constant.messages.getString(
                                "websocket.fuzzer.processor.scriptProcessor.panel.warnNoScript.title"),
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
