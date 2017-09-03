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

import org.apache.log4j.Logger;
import org.mozilla.zest.core.v1.ZestRequest;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.extension.fuzz.ExtensionFuzz;
import org.zaproxy.zap.extension.fuzz.FuzzerOptions;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.processors.sequence.HttpFuzzerMessageSequenceProcessorUIHandler;
import org.zaproxy.zap.extension.script.SequenceScript;
import org.zaproxy.zap.extension.zest.ZestIndexBasedSequenceRunner;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class HttpFuzzerSequenceLauncher{

    private final HttpFuzzerHandler httpFuzzerHandler;
    private final ExtensionFuzz extensionFuzz;
    private static final Logger logger = Logger.getLogger(HttpFuzzerSequenceLauncher.class);

    public HttpFuzzerSequenceLauncher(HttpFuzzerHandler httpFuzzerHandler, ExtensionFuzz extensionFuzz) {
        this.httpFuzzerHandler = httpFuzzerHandler;
        this.extensionFuzz = extensionFuzz;
    }

    public void showFuzzerDialogAndRun(SequenceScript sequenceScript, int messageIndex) throws IOException {
        HttpFuzzer fuzzer = showFuzzerDialog(sequenceScript, messageIndex);
        extensionFuzz.runFuzzer(httpFuzzerHandler, fuzzer);
    }

    public HttpFuzzer showFuzzerDialog(SequenceScript sequenceScript, int messageIndex) throws IOException {
        List<HttpFuzzerMessageProcessorUIHandler<HttpFuzzerMessageProcessor, ?>> messageProcessors = createHttpFuzzerMessageProcessors(sequenceScript);
        HttpFuzzerOptions httpFuzzerOptions = createHttpFuzzerOptions(sequenceScript);

        HttpMessage message = sequenceScript.getAllRequestsInScript().get(messageIndex);
        HttpMessage originalHttpMessage = sendAndReceiveOriginalHttpMessageForFuzzer(sequenceScript, message, httpFuzzerOptions);

        return httpFuzzerHandler.showFuzzerDialogImpl(originalHttpMessage, null, httpFuzzerOptions, messageProcessors);
    }

    private List<HttpFuzzerMessageProcessorUIHandler<HttpFuzzerMessageProcessor, ?>> createHttpFuzzerMessageProcessors(SequenceScript sequenceScript) {
        List<HttpFuzzerMessageProcessorUIHandler<HttpFuzzerMessageProcessor, ?>> messageProcessors = new ArrayList<>(httpFuzzerHandler.getMessageProcessors());
        ((List) messageProcessors).add(0, new HttpFuzzerMessageSequenceProcessorUIHandler(sequenceScript));
        return messageProcessors;
    }

    private HttpFuzzerOptions createHttpFuzzerOptions(SequenceScript sequenceScript) {
        FuzzerOptions defaultFuzzerOptions = extensionFuzz.getDefaultFuzzerOptions();
        FuzzerOptions fuzzerOptions = new FuzzerOptions(
                1,
                defaultFuzzerOptions.getRetriesOnIOError(),
                defaultFuzzerOptions.getMaxErrorsAllowed(),
                defaultFuzzerOptions.getSendMessageDelay(),
                defaultFuzzerOptions.getSendMessageDelayTimeUnit(),
                defaultFuzzerOptions.getPayloadsReplacementStrategy()
        );

        boolean followRedirects = false;
        if(sequenceScript instanceof ZestIndexBasedSequenceRunner){
            ZestRequest zestRequest = ((ZestIndexBasedSequenceRunner)sequenceScript).getRequest();
            followRedirects = zestRequest.isFollowRedirects();
        }

        return new HttpFuzzerOptions(fuzzerOptions, followRedirects, false, 100, true);
    }

    // Run the Sequence Script before fuzzing to have a basline (originalMessage), due to fuzzer
    // will not process the originalMessage with HttpFuzzerMessageSequenceProcessor which ensures
    // that pre and post scripts run too!
    private HttpMessage sendAndReceiveOriginalHttpMessageForFuzzer(SequenceScript sequenceScript, HttpMessage originalHttpMessage, HttpFuzzerOptions httpFuzzerOptions) throws IOException {
        HttpSender httpSender = HttpSenderForHttpFuzzerFactory.create(httpFuzzerOptions);
        HttpMessage tmpHttpMessage = sequenceScript.runSequenceBefore(originalHttpMessage.cloneAll(), null);
        try {
            HttpSenderForHttpFuzzerFactory.sendAndReceive(httpSender, httpFuzzerOptions, tmpHttpMessage);
        } catch (IOException ex) {
            logger.error("An exception occurred while sending the OriginalHttpMessage before starting the fuzzer:", ex);
            throw ex;
        }
        sequenceScript.runSequenceAfter(tmpHttpMessage, null);

        // Copy only the Response to HttpMessage template for fuzzing
        // Request may contain variables
        originalHttpMessage.setResponseHeader(tmpHttpMessage.getResponseHeader());
        originalHttpMessage.setResponseBody(tmpHttpMessage.getResponseBody());
        return originalHttpMessage;
    }

}
