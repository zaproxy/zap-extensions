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
package org.zaproxy.zap.extension.fuzz.httpfuzzer.processors.sequence;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.HttpFuzzResult;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.HttpFuzzerMessageProcessor;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.HttpFuzzerTaskProcessorUtils;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.ProcessingException;
import org.zaproxy.zap.extension.script.SequenceScript;

public class HttpFuzzerMessageSequenceProcessor implements HttpFuzzerMessageProcessor{

    public static final String NAME = Constant.messages.getString("fuzz.httpfuzzer.processor.sequence.name");
    public static final String DESCRIPTION = Constant.messages.getString("fuzz.httpfuzzer.processor.sequence.desc");
    private SequenceScript script;

    public HttpFuzzerMessageSequenceProcessor(SequenceScript script) {
        this.script = script;
    }

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public HttpMessage processMessage(HttpFuzzerTaskProcessorUtils utils, HttpMessage message) throws ProcessingException {
        HttpMessage messageWithReplacedTokens = script.runSequenceBefore(message,null);
        message.setRequestHeader(messageWithReplacedTokens.getRequestHeader());
        message.setRequestBody(messageWithReplacedTokens.getRequestBody());

        // This return value is not used. Update the parameter reference to modify the request!
        return message;
    }

    @Override
    public boolean processResult(HttpFuzzerTaskProcessorUtils utils, HttpFuzzResult result) throws ProcessingException {
        script.runSequenceAfter(result.getHttpMessage(),null);
        return true;
    }
}
