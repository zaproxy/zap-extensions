/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP Development Team
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
import org.zaproxy.zap.extension.fuzz.payloads.processor.SHA512HashProcessor;
import org.zaproxy.zap.extension.fuzz.payloads.ui.processors.AbstractStringHashProcessorUIPanel.AbstractStringHashProcessorUI;
import org.zaproxy.zap.extension.fuzz.payloads.ui.processors.SHA512HashProcessorUIHandler.SHA512HashProcessorUI;

public class SHA512HashProcessorUIHandler
        implements PayloadProcessorUIHandler<
                DefaultPayload, SHA512HashProcessor, SHA512HashProcessorUI> {

    private static final String PROCESSOR_NAME =
            Constant.messages.getString("fuzz.payload.processor.sha512Hash.name");

    @Override
    public String getName() {
        return PROCESSOR_NAME;
    }

    @Override
    public Class<SHA512HashProcessorUI> getPayloadProcessorUIClass() {
        return SHA512HashProcessorUI.class;
    }

    @Override
    public Class<SHA512HashProcessorUIPanel> getPayloadProcessorUIPanelClass() {
        return SHA512HashProcessorUIPanel.class;
    }

    @Override
    public SHA512HashProcessorUIPanel createPanel() {
        return new SHA512HashProcessorUIPanel();
    }

    public static class SHA512HashProcessorUI
            extends AbstractStringHashProcessorUI<SHA512HashProcessor> {

        public SHA512HashProcessorUI(Charset charset, boolean upperCase) {
            super(charset, upperCase);
        }

        @Override
        public Class<SHA512HashProcessor> getPayloadProcessorClass() {
            return SHA512HashProcessor.class;
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
                    "fuzz.payload.processor.sha512Hash.description", getCharset().name());
        }

        @Override
        public SHA512HashProcessor getPayloadProcessor() {
            return new SHA512HashProcessor(getCharset(), isUpperCase());
        }

        @Override
        public SHA512HashProcessorUI copy() {
            return this;
        }
    }

    public static class SHA512HashProcessorUIPanel
            extends AbstractStringHashProcessorUIPanel<SHA512HashProcessor, SHA512HashProcessorUI> {

        private final JPanel fieldsPanel;

        public SHA512HashProcessorUIPanel() {
            fieldsPanel = createDefaultFieldsPanel();
        }

        @Override
        public JPanel getComponent() {
            return fieldsPanel;
        }

        @Override
        public SHA512HashProcessorUI getPayloadProcessorUI() {
            return new SHA512HashProcessorUI(
                    (Charset) getCharsetComboBox().getSelectedItem(),
                    getUpperCaseCheckBox().isSelected());
        }

        @Override
        public SHA512HashProcessor getPayloadProcessor() {
            return new SHA512HashProcessor(
                    (Charset) getCharsetComboBox().getSelectedItem(),
                    getUpperCaseCheckBox().isSelected());
        }

        @Override
        public String getHelpTarget() {
            return "addon.fuzzer.processors";
        }
    }
}
