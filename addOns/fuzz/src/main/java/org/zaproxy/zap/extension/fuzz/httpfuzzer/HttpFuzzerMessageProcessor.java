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
package org.zaproxy.zap.extension.fuzz.httpfuzzer;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.fuzz.FuzzerMessageProcessor;

/** A {@code FuzzerMessageProcessor} of HTTP messages. */
public interface HttpFuzzerMessageProcessor extends FuzzerMessageProcessor<HttpMessage> {

    /**
     * Processes the fuzzed message before being forward to the server.
     *
     * @param utils utility class that contains methods that ease common tasks
     * @param message the fuzzed message that will be forward to the server
     * @return the message after being processed
     * @throws ProcessingException if an error occurs while processing the message
     */
    HttpMessage processMessage(HttpFuzzerTaskProcessorUtils utils, HttpMessage message)
            throws ProcessingException;

    /**
     * Processes the result of fuzzing a message, after being sent to the server and before being
     * displayed.
     *
     * @param utils utility class that contains methods that ease common tasks
     * @param result the result of sending the fuzzed message
     * @return {@code true} if the result should be accepted, {@code false} if discarded.
     * @throws ProcessingException if an error occurs while processing the result
     */
    boolean processResult(HttpFuzzerTaskProcessorUtils utils, HttpFuzzResult result)
            throws ProcessingException;
}
