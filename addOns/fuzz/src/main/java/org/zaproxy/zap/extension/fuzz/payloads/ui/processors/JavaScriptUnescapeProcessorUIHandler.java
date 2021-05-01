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

import javax.swing.JPanel;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.fuzz.payloads.DefaultPayload;
import org.zaproxy.zap.extension.fuzz.payloads.processor.JavaScriptUnescapeProcessor;
import org.zaproxy.zap.extension.fuzz.payloads.ui.processors.JavaScriptUnescapeProcessorUIHandler.JavaScriptUnescapeProcessorUI;

public class JavaScriptUnescapeProcessorUIHandler
        implements PayloadProcessorUIHandler<
                DefaultPayload, JavaScriptUnescapeProcessor, JavaScriptUnescapeProcessorUI> {

    private static final String PROCESSOR_NAME =
            Constant.messages.getString("fuzz.payload.processor.javascriptUnescape.name");

    @Override
    public String getName() {
        return PROCESSOR_NAME;
    }

    @Override
    public Class<JavaScriptUnescapeProcessorUI> getPayloadProcessorUIClass() {
        return JavaScriptUnescapeProcessorUI.class;
    }

    @Override
    public Class<JavaScriptUnescapeProcessorUIPanel> getPayloadProcessorUIPanelClass() {
        return JavaScriptUnescapeProcessorUIPanel.class;
    }

    @Override
    public JavaScriptUnescapeProcessorUIPanel createPanel() {
        return new JavaScriptUnescapeProcessorUIPanel();
    }

    public static class JavaScriptUnescapeProcessorUI
            implements PayloadProcessorUI<DefaultPayload, JavaScriptUnescapeProcessor> {

        public static final JavaScriptUnescapeProcessorUI INSTANCE =
                new JavaScriptUnescapeProcessorUI();

        public JavaScriptUnescapeProcessorUI() {}

        @Override
        public Class<JavaScriptUnescapeProcessor> getPayloadProcessorClass() {
            return JavaScriptUnescapeProcessor.class;
        }

        @Override
        public String getName() {
            return PROCESSOR_NAME;
        }

        @Override
        public boolean isMutable() {
            return false;
        }

        @Override
        public String getDescription() {
            return "";
        }

        @Override
        public JavaScriptUnescapeProcessor getPayloadProcessor() {
            return JavaScriptUnescapeProcessor.INSTANCE;
        }

        @Override
        public JavaScriptUnescapeProcessorUI copy() {
            return this;
        }
    }

    public static class JavaScriptUnescapeProcessorUIPanel
            extends AbstractProcessorUIPanel<
                    DefaultPayload, JavaScriptUnescapeProcessor, JavaScriptUnescapeProcessorUI> {

        private JPanel fieldsPanel;

        public JavaScriptUnescapeProcessorUIPanel() {
            fieldsPanel = new JPanel();
        }

        @Override
        public JPanel getComponent() {
            return fieldsPanel;
        }

        @Override
        public JavaScriptUnescapeProcessorUI getPayloadProcessorUI() {
            return JavaScriptUnescapeProcessorUI.INSTANCE;
        }

        @Override
        public void setPayloadProcessorUI(JavaScriptUnescapeProcessorUI payloadProcessorUI) {}

        @Override
        public JavaScriptUnescapeProcessor getPayloadProcessor() {
            return JavaScriptUnescapeProcessor.INSTANCE;
        }
    }
}
