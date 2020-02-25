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
import org.zaproxy.zap.extension.fuzz.payloads.processor.URLEncodeProcessor;
import org.zaproxy.zap.extension.fuzz.payloads.ui.processors.AbstractCharsetProcessorUIPanel.AbstractCharsetProcessorUI;
import org.zaproxy.zap.extension.fuzz.payloads.ui.processors.URLEncodeProcessorUIHandler.URLEncodeProcessorUI;

public class URLEncodeProcessorUIHandler
        implements PayloadProcessorUIHandler<
                DefaultPayload, URLEncodeProcessor, URLEncodeProcessorUI> {

    private static final String PROCESSOR_NAME =
            Constant.messages.getString("fuzz.payload.processor.urlEncode.name");

    @Override
    public String getName() {
        return PROCESSOR_NAME;
    }

    @Override
    public Class<URLEncodeProcessorUI> getPayloadProcessorUIClass() {
        return URLEncodeProcessorUI.class;
    }

    @Override
    public Class<URLEncodeProcessorUIPanel> getPayloadProcessorUIPanelClass() {
        return URLEncodeProcessorUIPanel.class;
    }

    @Override
    public URLEncodeProcessorUIPanel createPanel() {
        return new URLEncodeProcessorUIPanel();
    }

    public static class URLEncodeProcessorUI
            extends AbstractCharsetProcessorUI<DefaultPayload, URLEncodeProcessor> {

        public URLEncodeProcessorUI(Charset charset) {
            super(charset);
        }

        @Override
        public Class<URLEncodeProcessor> getPayloadProcessorClass() {
            return URLEncodeProcessor.class;
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
                    "fuzz.payload.processor.urlEncode.description", getCharset().name());
        }

        @Override
        public URLEncodeProcessor getPayloadProcessor() {
            return new URLEncodeProcessor(getCharset());
        }

        @Override
        public URLEncodeProcessorUI copy() {
            return this;
        }
    }

    public static class URLEncodeProcessorUIPanel
            extends AbstractCharsetProcessorUIPanel<
                    DefaultPayload, URLEncodeProcessor, URLEncodeProcessorUI> {

        private JPanel fieldsPanel;

        public URLEncodeProcessorUIPanel() {
            fieldsPanel = createDefaultFieldsPanel();
        }

        @Override
        public JPanel getComponent() {
            return fieldsPanel;
        }

        @Override
        public URLEncodeProcessorUI getPayloadProcessorUI() {
            return new URLEncodeProcessorUI((Charset) getCharsetComboBox().getSelectedItem());
        }

        @Override
        public URLEncodeProcessor getPayloadProcessor() {
            return new URLEncodeProcessor((Charset) getCharsetComboBox().getSelectedItem());
        }
    }
}
