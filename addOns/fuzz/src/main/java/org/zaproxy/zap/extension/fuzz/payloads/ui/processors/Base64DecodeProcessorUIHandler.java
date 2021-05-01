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
import org.zaproxy.zap.extension.fuzz.payloads.processor.Base64DecodeProcessor;
import org.zaproxy.zap.extension.fuzz.payloads.ui.processors.AbstractCharsetProcessorUIPanel.AbstractCharsetProcessorUI;
import org.zaproxy.zap.extension.fuzz.payloads.ui.processors.Base64DecodeProcessorUIHandler.Base64DecodeProcessorUI;

public class Base64DecodeProcessorUIHandler
        implements PayloadProcessorUIHandler<
                DefaultPayload, Base64DecodeProcessor, Base64DecodeProcessorUI> {

    private static final String PROCESSOR_NAME =
            Constant.messages.getString("fuzz.payload.processor.base64Decode.name");

    @Override
    public String getName() {
        return PROCESSOR_NAME;
    }

    @Override
    public Class<Base64DecodeProcessorUI> getPayloadProcessorUIClass() {
        return Base64DecodeProcessorUI.class;
    }

    @Override
    public Class<Base64DecodeProcessorUIPanel> getPayloadProcessorUIPanelClass() {
        return Base64DecodeProcessorUIPanel.class;
    }

    @Override
    public Base64DecodeProcessorUIPanel createPanel() {
        return new Base64DecodeProcessorUIPanel();
    }

    public static class Base64DecodeProcessorUI
            extends AbstractCharsetProcessorUI<DefaultPayload, Base64DecodeProcessor> {

        public Base64DecodeProcessorUI(Charset charset) {
            super(charset);
        }

        @Override
        public Class<Base64DecodeProcessor> getPayloadProcessorClass() {
            return Base64DecodeProcessor.class;
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
                    "fuzz.payload.processor.base64Decode.description", getCharset().name());
        }

        @Override
        public Base64DecodeProcessor getPayloadProcessor() {
            return new Base64DecodeProcessor(getCharset());
        }

        @Override
        public Base64DecodeProcessorUI copy() {
            return this;
        }
    }

    public static class Base64DecodeProcessorUIPanel
            extends AbstractCharsetProcessorUIPanel<
                    DefaultPayload, Base64DecodeProcessor, Base64DecodeProcessorUI> {

        private JPanel fieldsPanel;

        public Base64DecodeProcessorUIPanel() {
            fieldsPanel = createDefaultFieldsPanel();
        }

        @Override
        public JPanel getComponent() {
            return fieldsPanel;
        }

        @Override
        public Base64DecodeProcessorUI getPayloadProcessorUI() {
            return new Base64DecodeProcessorUI((Charset) getCharsetComboBox().getSelectedItem());
        }

        @Override
        public Base64DecodeProcessor getPayloadProcessor() {
            return new Base64DecodeProcessor((Charset) getCharsetComboBox().getSelectedItem());
        }
    }
}
