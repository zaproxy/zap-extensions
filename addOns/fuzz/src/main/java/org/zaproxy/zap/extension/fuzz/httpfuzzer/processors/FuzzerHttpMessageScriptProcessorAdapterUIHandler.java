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

import java.awt.event.ItemEvent;
import java.util.List;
import java.util.Map;
import javax.swing.GroupLayout;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.fuzz.ScriptUIEntry;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.AbstractHttpFuzzerMessageProcessorUIPanel;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.HttpFuzzerMessageProcessorUI;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.HttpFuzzerMessageProcessorUIHandler;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.processors.FuzzerHttpMessageScriptProcessorAdapterUIHandler.FuzzerHttpMessageScriptProcessorAdapterUI;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.utils.SortedComboBoxModel;
import org.zaproxy.zap.view.DynamicFieldsPanel;

public class FuzzerHttpMessageScriptProcessorAdapterUIHandler
        implements HttpFuzzerMessageProcessorUIHandler<
                FuzzerHttpMessageScriptProcessorAdapter,
                FuzzerHttpMessageScriptProcessorAdapterUI> {

    private static final String PROCESSOR_NAME =
            Constant.messages.getString("fuzz.httpfuzzer.processor.scriptProcessor.name");

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

    public static class FuzzerHttpMessageScriptProcessorAdapterUI
            implements HttpFuzzerMessageProcessorUI<FuzzerHttpMessageScriptProcessorAdapter> {

        private final ScriptWrapper scriptWrapper;
        private final Map<String, String> paramsValues;

        public FuzzerHttpMessageScriptProcessorAdapterUI(
                ScriptWrapper scriptWrapper, Map<String, String> paramsValues) {
            this.scriptWrapper = scriptWrapper;
            this.paramsValues = paramsValues;
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
            return new FuzzerHttpMessageScriptProcessorAdapter(scriptWrapper, paramsValues);
        }

        @Override
        public FuzzerHttpMessageScriptProcessorAdapterUI copy() {
            return new FuzzerHttpMessageScriptProcessorAdapterUI(scriptWrapper, paramsValues);
        }
    }

    public static class FuzzerHttpMessageScriptProcessorAdapterUIPanel
            extends AbstractHttpFuzzerMessageProcessorUIPanel<
                    FuzzerHttpMessageScriptProcessorAdapter,
                    FuzzerHttpMessageScriptProcessorAdapterUI> {

        private static final String SCRIPT_FIELD_LABEL =
                Constant.messages.getString(
                        "fuzz.httpfuzzer.processor.scriptProcessor.panel.script.label");

        private final JPanel fieldsPanel;
        private final JComboBox<ScriptUIEntry> scriptComboBox;
        private DynamicFieldsPanel scriptParametersPanel;

        public FuzzerHttpMessageScriptProcessorAdapterUIPanel(List<ScriptWrapper> scriptWrappers) {
            scriptComboBox = new JComboBox<>(new SortedComboBoxModel<ScriptUIEntry>());
            addScriptsToScriptComboBox(scriptWrappers);
            scriptComboBox.addItemListener(
                    e -> {
                        if (e.getStateChange() == ItemEvent.SELECTED) {
                            updateScriptParametersPanel((FuzzerProcessorScriptUIEntry) e.getItem());
                        }
                    });
            scriptParametersPanel = new DynamicFieldsPanel(HttpFuzzerProcessorScript.EMPTY_PARAMS);
            fieldsPanel = new JPanel();
            setupFieldsPanel();
        }

        private void addScriptsToScriptComboBox(List<ScriptWrapper> scriptWrappers) {
            for (ScriptWrapper scriptWrapper : scriptWrappers) {
                if (scriptWrapper.isEnabled()) {
                    scriptComboBox.addItem(new FuzzerProcessorScriptUIEntry(scriptWrapper));
                }
            }
            scriptComboBox.setSelectedIndex(-1);
        }

        private void setupFieldsPanel() {
            GroupLayout layout = new GroupLayout(fieldsPanel);
            fieldsPanel.setLayout(layout);
            layout.setAutoCreateGaps(true);

            JLabel scriptLabel = new JLabel(SCRIPT_FIELD_LABEL);
            scriptLabel.setLabelFor(scriptComboBox);

            JScrollPane parametersScrollPane = new JScrollPane(scriptParametersPanel);

            layout.setHorizontalGroup(
                    layout.createParallelGroup()
                            .addGroup(
                                    layout.createSequentialGroup()
                                            .addComponent(scriptLabel)
                                            .addComponent(scriptComboBox))
                            .addComponent(parametersScrollPane));

            layout.setVerticalGroup(
                    layout.createSequentialGroup()
                            .addGroup(
                                    layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                            .addComponent(scriptLabel)
                                            .addComponent(scriptComboBox))
                            .addComponent(parametersScrollPane));
        }

        private void updateScriptParametersPanel(FuzzerProcessorScriptUIEntry scriptUIEntry) {
            String[] requiredParameters = HttpFuzzerProcessorScript.EMPTY_PARAMS;
            String[] optionalParameters = HttpFuzzerProcessorScript.EMPTY_PARAMS;

            if (scriptUIEntry != null) {
                try {
                    if (!scriptUIEntry.isDataLoaded()) {
                        HttpFuzzerProcessorScript script =
                                HttpFuzzerProcessorScriptProxy.create(
                                        scriptUIEntry.getScriptWrapper());
                        scriptUIEntry.setParameters(
                                script.getRequiredParamsNames(), script.getOptionalParamsNames());
                    }
                    requiredParameters = scriptUIEntry.getRequiredParameters();
                    optionalParameters = scriptUIEntry.getOptionalParameters();
                } catch (Exception ex) {
                    scriptComboBox.setSelectedIndex(-1);
                    scriptComboBox.removeItem(scriptUIEntry);
                    showValidationMessageDialog(
                            Constant.messages.getString(
                                    "fuzz.httpfuzzer.processor.scriptProcessor.warnNoInterface.message",
                                    scriptUIEntry.getScriptWrapper().getName()),
                            Constant.messages.getString(
                                    "fuzz.httpfuzzer.processor.scriptProcessor.warnNoInterface.title"));
                }
            }

            scriptParametersPanel.setFields(requiredParameters, optionalParameters);

            fieldsPanel.revalidate();
            fieldsPanel.repaint();
        }

        @Override
        public JPanel getComponent() {
            return fieldsPanel;
        }

        @Override
        public void setFuzzerMessageProcessorUI(
                FuzzerHttpMessageScriptProcessorAdapterUI payloadProcessorUI) {
            scriptComboBox.setSelectedItem(
                    new FuzzerProcessorScriptUIEntry(payloadProcessorUI.getScriptWrapper()));
            scriptParametersPanel.bindFieldValues(payloadProcessorUI.paramsValues);
        }

        @Override
        public FuzzerHttpMessageScriptProcessorAdapterUI getFuzzerMessageProcessorUI() {
            FuzzerProcessorScriptUIEntry entry =
                    (FuzzerProcessorScriptUIEntry) scriptComboBox.getSelectedItem();
            return new FuzzerHttpMessageScriptProcessorAdapterUI(
                    entry.getScriptWrapper(), scriptParametersPanel.getFieldValues());
        }

        @Override
        public void clear() {
            scriptComboBox.setSelectedIndex(-1);
            scriptParametersPanel.clearFields();
        }

        @Override
        public boolean validate() {
            if (scriptComboBox.getSelectedIndex() == -1) {
                showValidationMessageDialog(
                        Constant.messages.getString(
                                "fuzz.httpfuzzer.processor.scriptProcessor.panel.warnNoScript.message"),
                        Constant.messages.getString(
                                "fuzz.httpfuzzer.processor.scriptProcessor.panel.warnNoScript.title"));
                return false;
            }

            try {
                scriptParametersPanel.validateFields();
            } catch (IllegalStateException ex) {
                showValidationMessageDialog(
                        ex.getMessage(),
                        Constant.messages.getString(
                                "fuzz.httpfuzzer.processor.scriptProcessor.panel.warn.title"));
                return false;
            }
            return true;
        }

        private void showValidationMessageDialog(Object message, String title) {
            JOptionPane.showMessageDialog(null, message, title, JOptionPane.INFORMATION_MESSAGE);
            scriptComboBox.requestFocusInWindow();
        }

        private static class FuzzerProcessorScriptUIEntry extends ScriptUIEntry {

            private String[] requiredParameters;
            private String[] optionalParameters;
            private boolean dataLoaded;

            public FuzzerProcessorScriptUIEntry(ScriptWrapper scriptWrapper) {
                super(scriptWrapper);
            }

            public boolean isDataLoaded() {
                return dataLoaded;
            }

            public void setParameters(String[] requiredParameters, String[] optionalParameters) {
                this.requiredParameters = requiredParameters;
                this.optionalParameters = optionalParameters;
                dataLoaded = true;
            }

            public String[] getRequiredParameters() {
                return requiredParameters;
            }

            public String[] getOptionalParameters() {
                return optionalParameters;
            }
        }
    }
}
