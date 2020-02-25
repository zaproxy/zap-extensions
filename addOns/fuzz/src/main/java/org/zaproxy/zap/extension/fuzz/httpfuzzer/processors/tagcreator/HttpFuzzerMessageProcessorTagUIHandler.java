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
package org.zaproxy.zap.extension.fuzz.httpfuzzer.processors.tagcreator;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.HttpFuzzerMessageProcessorUIHandler;

public class HttpFuzzerMessageProcessorTagUIHandler
        implements HttpFuzzerMessageProcessorUIHandler<
                HttpFuzzerMessageProcessorTagCreator, HttpFuzzerMessageProcessorTagUI> {

    private static final String NAME = HttpFuzzerMessageProcessorTagCreator.NAME;

    @Override
    public boolean isEnabled(HttpMessage message) {
        return true;
    }

    @Override
    public boolean isDefault() {
        return false;
    }

    @Override
    public HttpFuzzerMessageProcessorTagUI createDefault() {
        return null;
    }

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public Class<HttpMessage> getMessageType() {
        return HttpMessage.class;
    }

    @Override
    public Class<HttpFuzzerMessageProcessorTagCreator> getFuzzerMessageProcessorType() {
        return HttpFuzzerMessageProcessorTagCreator.class;
    }

    @Override
    public Class<HttpFuzzerMessageProcessorTagUI> getFuzzerMessageProcessorUIType() {
        return HttpFuzzerMessageProcessorTagUI.class;
    }

    @Override
    public HttpFuzzerMessageProcessorTagUIPanel createPanel() {
        return new HttpFuzzerMessageProcessorTagUIPanel();
    }
}
