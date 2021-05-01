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

import java.io.IOException;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.extension.fuzz.AbstractFuzzerTask;

public class HttpFuzzerTask extends AbstractFuzzerTask<HttpMessage> {

    private static final Logger LOGGER = LogManager.getLogger(HttpFuzzerTask.class);

    private final HttpFuzzerOptions options;

    public HttpFuzzerTask(long id, HttpFuzzer parent, HttpMessage message, List<Object> payloads) {
        super(id, parent, message, payloads);

        options = parent.getFuzzerOptions();
    }

    @Override
    protected HttpFuzzer getParent() {
        return (HttpFuzzer) super.getParent();
    }

    @Override
    protected void runImpl(HttpMessage message, List<Object> payloads) {
        getParent().preProcessMessage(getId(), message, payloads);
        HttpMessage messageSent = sendMessage(getParent().getHttpSender(), message);
        if (messageSent == null) {
            return;
        }
        getParent().messageSent(getId(), messageSent);

        HttpFuzzResult result =
                new HttpFuzzResult(
                        getId(),
                        Constant.messages.getString("fuzz.httpfuzzer.messagetype.result"),
                        messageSent,
                        payloads);
        if (getParent().processResult(getId(), result)) {
            getParent().fuzzResultAvailable(result);
        }
    }

    private HttpMessage sendMessage(HttpSender sender, HttpMessage message) {
        // Do not allow for now
        // if (options.isFollowRedirects() && options.isShowRedirectMessages()) {
        // return sendMessageWithManualRedirects(message);
        // }

        int maxRetries = options.getRetriesOnIOError();
        for (int retryCount = 0; ; ) {
            if (getParent().isStopped()) {
                LOGGER.debug("Message not send, fuzzer is stooped.");
                return null;
            }

            try {
                sender.sendAndReceive(message);

                return message;
            } catch (IOException e) {
                ++retryCount;
                if (retryCount >= maxRetries) {
                    String retriesInfo =
                            maxRetries <= 0
                                    ? ""
                                    : " After retry " + retryCount + " of " + maxRetries + ".";
                    LOGGER.warn(
                            "Failed to send a fuzzed message: '{}'.{}",
                            e.getMessage(),
                            retriesInfo);

                    getParent()
                            .increaseErrorCount(
                                    getId(),
                                    Constant.messages.getString("fuzz.httpfuzzer.error.source"),
                                    Constant.messages.getString(
                                            "fuzz.httpfuzzer.error.message",
                                            e.getLocalizedMessage()));
                    return null;
                }

                LOGGER.debug(
                        "Failed to send HTTP fuzzed message '{}'. Send retry {} of {}.",
                        e.getMessage(),
                        retryCount,
                        maxRetries);
            }
        }
    }
}
