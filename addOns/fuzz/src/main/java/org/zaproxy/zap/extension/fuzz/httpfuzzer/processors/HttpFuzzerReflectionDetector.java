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

import java.util.ArrayList;
import java.util.List;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.HttpFuzzResult;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.HttpFuzzerMessageProcessor;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.HttpFuzzerTaskProcessorUtils;

public class HttpFuzzerReflectionDetector implements HttpFuzzerMessageProcessor {

    public static final String NAME =
            Constant.messages.getString("fuzz.httpfuzzer.processor.reflection.name");

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public HttpMessage processMessage(HttpFuzzerTaskProcessorUtils utils, HttpMessage message) {
        return message;
    }

    @Override
    public boolean processResult(HttpFuzzerTaskProcessorUtils utils, HttpFuzzResult fuzzResult) {
        List<String> reflectedPayloads =
                getPayloadsReflected(
                        utils.getOriginalMessage(),
                        fuzzResult.getHttpMessage(),
                        fuzzResult.getPayloads());
        if (!reflectedPayloads.isEmpty()) {
            fuzzResult.addCustomState(
                    HttpFuzzerReflectionDetectorStateHighlighter.REFLECTED_CUSTOM_STATE_KEY,
                    reflectedPayloads);
        }
        return true;
    }

    private List<String> getPayloadsReflected(
            HttpMessage originalMessage, HttpMessage httpMessage, List<Object> payloads) {
        List<String> reflected = new ArrayList<>();
        String originalResponseBody = originalMessage.getResponseBody().toString();
        String fuzzedResponseBody = httpMessage.getResponseBody().toString();
        for (Object payload : payloads) {
            String strPayload = payload.toString();
            if (!strPayload.isEmpty()) {
                int pos = originalResponseBody.indexOf(strPayload);
                if (fuzzedResponseBody.indexOf(strPayload, pos) != -1) {
                    reflected.add(strPayload);
                    break;
                }
            }
        }
        return reflected;
    }
}
