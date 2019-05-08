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
import org.zaproxy.zap.extension.fuzz.payloads.processor.MD5HashProcessor;
import org.zaproxy.zap.extension.fuzz.payloads.ui.processors.AbstractStringHashProcessorUIPanel.AbstractStringHashProcessorUI;
import org.zaproxy.zap.extension.fuzz.payloads.ui.processors.MD5HashProcessorUIHandler.MD5HashProcessorUI;

public class MD5HashProcessorUIHandler
        implements PayloadProcessorUIHandler<DefaultPayload, MD5HashProcessor, MD5HashProcessorUI> {

    private static final String PROCESSOR_NAME =
            Constant.messages.getString("fuzz.payload.processor.md5Hash.name");

    @Override
    public String getName() {
        return PROCESSOR_NAME;
    }

    @Override
    public Class<MD5HashProcessorUI> getPayloadProcessorUIClass() {
        return MD5HashProcessorUI.class;
    }

    @Override
    public Class<MD5HashProcessorUIPanel> getPayloadProcessorUIPanelClass() {
        return MD5HashProcessorUIPanel.class;
    }

    @Override
    public MD5HashProcessorUIPanel createPanel() {
        return new MD5HashProcessorUIPanel();
    }

    public static class MD5HashProcessorUI extends AbstractStringHashProcessorUI<MD5HashProcessor> {

        public MD5HashProcessorUI(Charset charset, boolean upperCase) {
            super(charset, upperCase);
        }

        @Override
        public Class<MD5HashProcessor> getPayloadProcessorClass() {
            return MD5HashProcessor.class;
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
                    "fuzz.payload.processor.md5Hash.description", getCharset().name());
        }

        @Override
        public MD5HashProcessor getPayloadProcessor() {
            return new MD5HashProcessor(getCharset(), isUpperCase());
        }

        @Override
        public MD5HashProcessorUI copy() {
            return this;
        }
    }

    public static class MD5HashProcessorUIPanel
            extends AbstractStringHashProcessorUIPanel<MD5HashProcessor, MD5HashProcessorUI> {

        private final JPanel fieldsPanel;

        public MD5HashProcessorUIPanel() {
            fieldsPanel = createDefaultFieldsPanel();
        }

        @Override
        public JPanel getComponent() {
            return fieldsPanel;
        }

        @Override
        public MD5HashProcessorUI getPayloadProcessorUI() {
            return new MD5HashProcessorUI(
                    (Charset) getCharsetComboBox().getSelectedItem(),
                    getUpperCaseCheckBox().isSelected());
        }

        @Override
        public MD5HashProcessor getPayloadProcessor() {
            return new MD5HashProcessor(
                    (Charset) getCharsetComboBox().getSelectedItem(),
                    getUpperCaseCheckBox().isSelected());
        }
    }
}
