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
import org.zaproxy.zap.extension.fuzz.payloads.processor.URLDecodeProcessor;
import org.zaproxy.zap.extension.fuzz.payloads.ui.processors.AbstractCharsetProcessorUIPanel.AbstractCharsetProcessorUI;
import org.zaproxy.zap.extension.fuzz.payloads.ui.processors.URLDecodeProcessorUIHandler.URLDecodeProcessorUI;

public class URLDecodeProcessorUIHandler
        implements PayloadProcessorUIHandler<
                DefaultPayload, URLDecodeProcessor, URLDecodeProcessorUI> {

    private static final String PROCESSOR_NAME =
            Constant.messages.getString("fuzz.payload.processor.urlDecode.name");

    @Override
    public String getName() {
        return PROCESSOR_NAME;
    }

    @Override
    public Class<URLDecodeProcessorUI> getPayloadProcessorUIClass() {
        return URLDecodeProcessorUI.class;
    }

    @Override
    public Class<URLDecodeProcessorUIPanel> getPayloadProcessorUIPanelClass() {
        return URLDecodeProcessorUIPanel.class;
    }

    @Override
    public URLDecodeProcessorUIPanel createPanel() {
        return new URLDecodeProcessorUIPanel();
    }

    public static class URLDecodeProcessorUI
            extends AbstractCharsetProcessorUI<DefaultPayload, URLDecodeProcessor> {

        public URLDecodeProcessorUI(Charset charset) {
            super(charset);
        }

        @Override
        public Class<URLDecodeProcessor> getPayloadProcessorClass() {
            return URLDecodeProcessor.class;
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
                    "fuzz.payload.processor.urlDecode.description", getCharset().name());
        }

        @Override
        public URLDecodeProcessor getPayloadProcessor() {
            return new URLDecodeProcessor(getCharset());
        }

        @Override
        public URLDecodeProcessorUI copy() {
            return this;
        }
    }

    public static class URLDecodeProcessorUIPanel
            extends AbstractCharsetProcessorUIPanel<
                    DefaultPayload, URLDecodeProcessor, URLDecodeProcessorUI> {

        private JPanel fieldsPanel;

        public URLDecodeProcessorUIPanel() {
            fieldsPanel = createDefaultFieldsPanel();
        }

        @Override
        public JPanel getComponent() {
            return fieldsPanel;
        }

        @Override
        public URLDecodeProcessorUI getPayloadProcessorUI() {
            return new URLDecodeProcessorUI((Charset) getCharsetComboBox().getSelectedItem());
        }

        @Override
        public URLDecodeProcessor getPayloadProcessor() {
            return new URLDecodeProcessor((Charset) getCharsetComboBox().getSelectedItem());
        }
    }
}
