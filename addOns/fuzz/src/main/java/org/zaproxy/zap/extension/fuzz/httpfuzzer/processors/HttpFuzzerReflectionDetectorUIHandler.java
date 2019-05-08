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

import javax.swing.JPanel;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.AbstractHttpFuzzerMessageProcessorUIPanel;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.HttpFuzzerMessageProcessorUI;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.HttpFuzzerMessageProcessorUIHandler;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.processors.HttpFuzzerReflectionDetectorUIHandler.HttpFuzzerReflectionDetectorUI;

public class HttpFuzzerReflectionDetectorUIHandler
        implements HttpFuzzerMessageProcessorUIHandler<
                HttpFuzzerReflectionDetector, HttpFuzzerReflectionDetectorUI> {

    @Override
    public String getName() {
        return HttpFuzzerReflectionDetector.NAME;
    }

    @Override
    public boolean isEnabled(HttpMessage message) {
        return true;
    }

    @Override
    public boolean isDefault() {
        return true;
    }

    @Override
    public HttpFuzzerReflectionDetectorUI createDefault() {
        return HttpFuzzerReflectionDetectorUI.INSTANCE;
    }

    @Override
    public Class<HttpMessage> getMessageType() {
        return HttpMessage.class;
    }

    @Override
    public Class<HttpFuzzerReflectionDetector> getFuzzerMessageProcessorType() {
        return HttpFuzzerReflectionDetector.class;
    }

    @Override
    public Class<HttpFuzzerReflectionDetectorUI> getFuzzerMessageProcessorUIType() {
        return HttpFuzzerReflectionDetectorUI.class;
    }

    @Override
    public HttpFuzzerReflectionDetectorUIPanel createPanel() {
        return new HttpFuzzerReflectionDetectorUIPanel();
    }

    public static class HttpFuzzerReflectionDetectorUI
            implements HttpFuzzerMessageProcessorUI<HttpFuzzerReflectionDetector> {

        public static final HttpFuzzerReflectionDetectorUI INSTANCE =
                new HttpFuzzerReflectionDetectorUI();

        public HttpFuzzerReflectionDetectorUI() {}

        @Override
        public String getName() {
            return HttpFuzzerReflectionDetector.NAME;
        }

        @Override
        public boolean isMutable() {
            return false;
        }

        @Override
        public String getDescription() {
            return Constant.messages.getString("fuzz.httpfuzzer.processor.reflection.description");
        }

        @Override
        public HttpFuzzerReflectionDetector getFuzzerMessageProcessor() {
            return new HttpFuzzerReflectionDetector();
        }

        @Override
        public HttpFuzzerReflectionDetectorUI copy() {
            return this;
        }
    }

    public static class HttpFuzzerReflectionDetectorUIPanel
            extends AbstractHttpFuzzerMessageProcessorUIPanel<
                    HttpFuzzerReflectionDetector, HttpFuzzerReflectionDetectorUI> {

        private JPanel fieldsPanel;

        public HttpFuzzerReflectionDetectorUIPanel() {
            fieldsPanel = new JPanel();
        }

        @Override
        public JPanel getComponent() {
            return fieldsPanel;
        }

        @Override
        public void setFuzzerMessageProcessorUI(
                HttpFuzzerReflectionDetectorUI payloadProcessorUI) {}

        @Override
        public HttpFuzzerReflectionDetectorUI getFuzzerMessageProcessorUI() {
            return HttpFuzzerReflectionDetectorUI.INSTANCE;
        }
    }
}
