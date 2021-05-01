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
import org.zaproxy.zap.extension.fuzz.payloads.processor.JavaScriptEscapeProcessor;
import org.zaproxy.zap.extension.fuzz.payloads.ui.processors.JavaScriptEscapeProcessorUIHandler.JavaScriptEscapeProcessorUI;

public class JavaScriptEscapeProcessorUIHandler
        implements PayloadProcessorUIHandler<
                DefaultPayload, JavaScriptEscapeProcessor, JavaScriptEscapeProcessorUI> {

    private static final String PROCESSOR_NAME =
            Constant.messages.getString("fuzz.payload.processor.javascriptEscape.name");

    @Override
    public String getName() {
        return PROCESSOR_NAME;
    }

    @Override
    public Class<JavaScriptEscapeProcessorUI> getPayloadProcessorUIClass() {
        return JavaScriptEscapeProcessorUI.class;
    }

    @Override
    public Class<JavaScriptEscapeProcessorUIPanel> getPayloadProcessorUIPanelClass() {
        return JavaScriptEscapeProcessorUIPanel.class;
    }

    @Override
    public JavaScriptEscapeProcessorUIPanel createPanel() {
        return new JavaScriptEscapeProcessorUIPanel();
    }

    public static class JavaScriptEscapeProcessorUI
            implements PayloadProcessorUI<DefaultPayload, JavaScriptEscapeProcessor> {

        public static final JavaScriptEscapeProcessorUI INSTANCE =
                new JavaScriptEscapeProcessorUI();

        public JavaScriptEscapeProcessorUI() {}

        @Override
        public Class<JavaScriptEscapeProcessor> getPayloadProcessorClass() {
            return JavaScriptEscapeProcessor.class;
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
        public JavaScriptEscapeProcessor getPayloadProcessor() {
            return JavaScriptEscapeProcessor.INSTANCE;
        }

        @Override
        public JavaScriptEscapeProcessorUI copy() {
            return this;
        }
    }

    public static class JavaScriptEscapeProcessorUIPanel
            extends AbstractProcessorUIPanel<
                    DefaultPayload, JavaScriptEscapeProcessor, JavaScriptEscapeProcessorUI> {

        private JPanel fieldsPanel;

        public JavaScriptEscapeProcessorUIPanel() {
            fieldsPanel = new JPanel();
        }

        @Override
        public JPanel getComponent() {
            return fieldsPanel;
        }

        @Override
        public JavaScriptEscapeProcessorUI getPayloadProcessorUI() {
            return JavaScriptEscapeProcessorUI.INSTANCE;
        }

        @Override
        public void setPayloadProcessorUI(JavaScriptEscapeProcessorUI payloadProcessorUI) {}

        @Override
        public JavaScriptEscapeProcessor getPayloadProcessor() {
            return JavaScriptEscapeProcessor.INSTANCE;
        }
    }
}
