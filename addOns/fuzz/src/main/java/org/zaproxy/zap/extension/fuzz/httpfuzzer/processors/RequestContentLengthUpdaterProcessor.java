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

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.HttpFuzzResult;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.HttpFuzzerMessageProcessor;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.HttpFuzzerTaskProcessorUtils;

public class RequestContentLengthUpdaterProcessor implements HttpFuzzerMessageProcessor {

    public static final String NAME =
            Constant.messages.getString(
                    "fuzz.httpfuzzer.processor.requestContentLengthUpdater.name");

    private static RequestContentLengthUpdaterProcessor instance;

    private final String method;

    public static RequestContentLengthUpdaterProcessor getInstance() {
        if (instance == null) {
            createInstance();
        }
        return instance;
    }

    private static synchronized void createInstance() {
        if (instance == null) {
            instance = new RequestContentLengthUpdaterProcessor();
        }
    }

    public RequestContentLengthUpdaterProcessor() {
        this(null);
    }

    public RequestContentLengthUpdaterProcessor(String method) {
        this.method = method;
    }

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public HttpMessage processMessage(HttpFuzzerTaskProcessorUtils utils, HttpMessage message) {
        if (method != null && !method.equals(message.getRequestHeader().getMethod())) {
            return message;
        }

        if (message.getRequestHeader().getHeader(HttpHeader.CONTENT_LENGTH) != null
                || message.getRequestBody().length() != 0) {
            message.getRequestHeader().setContentLength(message.getRequestBody().length());
        }

        return message;
    }

    @Override
    public boolean processResult(HttpFuzzerTaskProcessorUtils utils, HttpFuzzResult fuzzResult) {
        return true;
    }
}
