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

import java.nio.charset.Charset;
import javax.swing.JPanel;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.fuzz.payloads.DefaultPayload;
import org.zaproxy.zap.extension.fuzz.payloads.processor.SHA256HashProcessor;
import org.zaproxy.zap.extension.fuzz.payloads.ui.processors.AbstractStringHashProcessorUIPanel.AbstractStringHashProcessorUI;
import org.zaproxy.zap.extension.fuzz.payloads.ui.processors.SHA256HashProcessorUIHandler.SHA256HashProcessorUI;

public class SHA256HashProcessorUIHandler
        implements PayloadProcessorUIHandler<
                DefaultPayload, SHA256HashProcessor, SHA256HashProcessorUI> {

    private static final String PROCESSOR_NAME =
            Constant.messages.getString("fuzz.payload.processor.sha256Hash.name");

    @Override
    public String getName() {
        return PROCESSOR_NAME;
    }

    @Override
    public Class<SHA256HashProcessorUI> getPayloadProcessorUIClass() {
        return SHA256HashProcessorUI.class;
    }

    @Override
    public Class<SHA256HashProcessorUIPanel> getPayloadProcessorUIPanelClass() {
        return SHA256HashProcessorUIPanel.class;
    }

    @Override
    public SHA256HashProcessorUIPanel createPanel() {
        return new SHA256HashProcessorUIPanel();
    }

    public static class SHA256HashProcessorUI
            extends AbstractStringHashProcessorUI<SHA256HashProcessor> {

        public SHA256HashProcessorUI(Charset charset, boolean upperCase) {
            super(charset, upperCase);
        }

        @Override
        public Class<SHA256HashProcessor> getPayloadProcessorClass() {
            return SHA256HashProcessor.class;
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
            return Constant.messages.getString(
                    "fuzz.payload.processor.sha256Hash.description", getCharset().name());
        }

        @Override
        public SHA256HashProcessor getPayloadProcessor() {
            return new SHA256HashProcessor(getCharset(), isUpperCase());
        }

        @Override
        public SHA256HashProcessorUI copy() {
            return this;
        }
    }

    public static class SHA256HashProcessorUIPanel
            extends AbstractStringHashProcessorUIPanel<SHA256HashProcessor, SHA256HashProcessorUI> {

        private final JPanel fieldsPanel;

        public SHA256HashProcessorUIPanel() {
            fieldsPanel = createDefaultFieldsPanel();
        }

        @Override
        public JPanel getComponent() {
            return fieldsPanel;
        }

        @Override
        public SHA256HashProcessorUI getPayloadProcessorUI() {
            return new SHA256HashProcessorUI(
                    (Charset) getCharsetComboBox().getSelectedItem(),
                    getUpperCaseCheckBox().isSelected());
        }

        @Override
        public SHA256HashProcessor getPayloadProcessor() {
            return new SHA256HashProcessor(
                    (Charset) getCharsetComboBox().getSelectedItem(),
                    getUpperCaseCheckBox().isSelected());
        }
    }
}
