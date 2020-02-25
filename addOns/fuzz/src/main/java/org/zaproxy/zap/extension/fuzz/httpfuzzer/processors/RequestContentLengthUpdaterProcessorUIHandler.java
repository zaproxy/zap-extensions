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
import org.zaproxy.zap.extension.fuzz.httpfuzzer.processors.RequestContentLengthUpdaterProcessorUIHandler.RequestContentLengthUpdatedProcessorUI;

public class RequestContentLengthUpdaterProcessorUIHandler
        implements HttpFuzzerMessageProcessorUIHandler<
                RequestContentLengthUpdaterProcessor, RequestContentLengthUpdatedProcessorUI> {

    @Override
    public String getName() {
        return RequestContentLengthUpdaterProcessor.NAME;
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
    public RequestContentLengthUpdatedProcessorUI createDefault() {
        return RequestContentLengthUpdatedProcessorUI.INSTANCE;
    }

    @Override
    public Class<HttpMessage> getMessageType() {
        return HttpMessage.class;
    }

    @Override
    public Class<RequestContentLengthUpdaterProcessor> getFuzzerMessageProcessorType() {
        return RequestContentLengthUpdaterProcessor.class;
    }

    @Override
    public Class<RequestContentLengthUpdatedProcessorUI> getFuzzerMessageProcessorUIType() {
        return RequestContentLengthUpdatedProcessorUI.class;
    }

    @Override
    public RequestContentLengthUpdatedProcessorUIPanel createPanel() {
        return new RequestContentLengthUpdatedProcessorUIPanel();
    }

    public static class RequestContentLengthUpdatedProcessorUI
            implements HttpFuzzerMessageProcessorUI<RequestContentLengthUpdaterProcessor> {

        public static final RequestContentLengthUpdatedProcessorUI INSTANCE =
                new RequestContentLengthUpdatedProcessorUI();

        public RequestContentLengthUpdatedProcessorUI() {}

        @Override
        public String getName() {
            return RequestContentLengthUpdaterProcessor.NAME;
        }

        @Override
        public boolean isMutable() {
            return false;
        }

        @Override
        public String getDescription() {
            return Constant.messages.getString(
                    "fuzz.httpfuzzer.processor.requestContentLengthUpdater.description");
        }

        @Override
        public RequestContentLengthUpdaterProcessor getFuzzerMessageProcessor() {
            return RequestContentLengthUpdaterProcessor.getInstance();
        }

        @Override
        public RequestContentLengthUpdatedProcessorUI copy() {
            return this;
        }
    }

    public static class RequestContentLengthUpdatedProcessorUIPanel
            extends AbstractHttpFuzzerMessageProcessorUIPanel<
                    RequestContentLengthUpdaterProcessor, RequestContentLengthUpdatedProcessorUI> {

        private JPanel fieldsPanel;

        public RequestContentLengthUpdatedProcessorUIPanel() {
            fieldsPanel = new JPanel();
        }

        @Override
        public JPanel getComponent() {
            return fieldsPanel;
        }

        @Override
        public void setFuzzerMessageProcessorUI(
                RequestContentLengthUpdatedProcessorUI payloadProcessorUI) {}

        @Override
        public RequestContentLengthUpdatedProcessorUI getFuzzerMessageProcessorUI() {
            return RequestContentLengthUpdatedProcessorUI.INSTANCE;
        }
    }
}
