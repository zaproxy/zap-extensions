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
import org.zaproxy.zap.extension.fuzz.payloads.processor.SHA1HashProcessor;
import org.zaproxy.zap.extension.fuzz.payloads.ui.processors.AbstractStringHashProcessorUIPanel.AbstractStringHashProcessorUI;
import org.zaproxy.zap.extension.fuzz.payloads.ui.processors.SHA1HashProcessorUIHandler.SHA1HashProcessorUI;

public class SHA1HashProcessorUIHandler
        implements PayloadProcessorUIHandler<
                DefaultPayload, SHA1HashProcessor, SHA1HashProcessorUI> {

    private static final String PROCESSOR_NAME =
            Constant.messages.getString("fuzz.payload.processor.sha1Hash.name");

    @Override
    public String getName() {
        return PROCESSOR_NAME;
    }

    @Override
    public Class<SHA1HashProcessorUI> getPayloadProcessorUIClass() {
        return SHA1HashProcessorUI.class;
    }

    @Override
    public Class<SHA1HashProcessorUIPanel> getPayloadProcessorUIPanelClass() {
        return SHA1HashProcessorUIPanel.class;
    }

    @Override
    public SHA1HashProcessorUIPanel createPanel() {
        return new SHA1HashProcessorUIPanel();
    }

    public static class SHA1HashProcessorUI
            extends AbstractStringHashProcessorUI<SHA1HashProcessor> {

        public SHA1HashProcessorUI(Charset charset, boolean upperCase) {
            super(charset, upperCase);
        }

        @Override
        public Class<SHA1HashProcessor> getPayloadProcessorClass() {
            return SHA1HashProcessor.class;
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
                    "fuzz.payload.processor.sha1Hash.description", getCharset().name());
        }

        @Override
        public SHA1HashProcessor getPayloadProcessor() {
            return new SHA1HashProcessor(getCharset(), isUpperCase());
        }

        @Override
        public SHA1HashProcessorUI copy() {
            return this;
        }
    }

    public static class SHA1HashProcessorUIPanel
            extends AbstractStringHashProcessorUIPanel<SHA1HashProcessor, SHA1HashProcessorUI> {

        private final JPanel fieldsPanel;

        public SHA1HashProcessorUIPanel() {
            fieldsPanel = createDefaultFieldsPanel();
        }

        @Override
        public JPanel getComponent() {
            return fieldsPanel;
        }

        @Override
        public SHA1HashProcessorUI getPayloadProcessorUI() {
            return new SHA1HashProcessorUI(
                    (Charset) getCharsetComboBox().getSelectedItem(),
                    getUpperCaseCheckBox().isSelected());
        }

        @Override
        public SHA1HashProcessor getPayloadProcessor() {
            return new SHA1HashProcessor(
                    (Charset) getCharsetComboBox().getSelectedItem(),
                    getUpperCaseCheckBox().isSelected());
        }
    }
}
