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
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.extension.alert.ExtensionAlert;
import org.zaproxy.zap.extension.fuzz.AbstractFuzzer;
import org.zaproxy.zap.extension.fuzz.ExtensionFuzz;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.ui.HttpFuzzerErrorsTableModel;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.ui.HttpFuzzerResultsTableModel;
import org.zaproxy.zap.extension.fuzz.messagelocations.MessageLocationReplacement;
import org.zaproxy.zap.extension.fuzz.messagelocations.MessageLocationReplacementGenerator;
import org.zaproxy.zap.extension.fuzz.messagelocations.MultipleMessageLocationsReplacer;
import org.zaproxy.zap.extension.search.SearchResult;
import org.zaproxy.zap.utils.Stats;

public class HttpFuzzer extends AbstractFuzzer<HttpMessage> {

    private final Session currentSession;
    private final HttpSender httpSender;
    private final HttpFuzzerResultsTableModel messagesModel;
    private final HttpFuzzerErrorsTableModel errorsModel;
    private final List<HttpFuzzerListener> listeners;
    private final List<HttpFuzzerMessageProcessor> messageProcessors;
    private final AtomicInteger messagesSentCounter;
    private final HttpMessage originalMessage;

    public HttpFuzzer(
            String fuzzerScanName,
            HttpFuzzerOptions fuzzerOptions,
            HttpMessage message,
            List<MessageLocationReplacementGenerator<?, MessageLocationReplacement<?>>>
                    fuzzLocations,
            MultipleMessageLocationsReplacer<HttpMessage> multipleMessageLocationsReplacer,
            List<HttpFuzzerMessageProcessor> messageProcessors) {
        super(
                fuzzerScanName,
                fuzzerOptions,
                message,
                fuzzLocations,
                multipleMessageLocationsReplacer);

        this.messageProcessors =
                messageProcessors.isEmpty()
                        ? Collections.<HttpFuzzerMessageProcessor>emptyList()
                        : Collections.synchronizedList(new ArrayList<>(messageProcessors));
        currentSession = Model.getSingleton().getSession();

        httpSender =
                new HttpSender(
                        Model.getSingleton().getOptionsParam().getConnectionParam(),
                        true,
                        HttpSender.FUZZER_INITIATOR);

        if (fuzzerOptions.isFollowRedirects()) {
            httpSender.setFollowRedirect(fuzzerOptions.isFollowRedirects());
            httpSender.setMaxRedirects(fuzzerOptions.getMaximumRedirects());
        }

        httpSender.setRemoveUserDefinedAuthHeaders(true);
        // Retries are handled by the fuzzer tasks.
        httpSender.setMaxRetriesOnIOError(0);

        this.originalMessage = message;

        messagesModel = new HttpFuzzerResultsTableModel();
        errorsModel = new HttpFuzzerErrorsTableModel();
        listeners = new ArrayList<>(1);
        messagesSentCounter = new AtomicInteger(0);

        if (originalMessage.getResponseHeader().isEmpty()) {
            try {
                httpSender.sendAndReceive(originalMessage);
                messageSent(0, message);
            } catch (IOException e) {
                logger.debug("Failed to obtain the response of original message: ", e);
                increaseErrorCount(
                        0,
                        Constant.messages.getString(
                                "fuzz.httpfuzzer.results.error.source.httpfuzzer"),
                        Constant.messages.getString(
                                "fuzz.httpfuzzer.results.error.message.failedSendOriginalMessage",
                                e.getLocalizedMessage()));
            }
        }

        fuzzResultAvailable(
                new HttpFuzzResult(
                        0,
                        Constant.messages.getString(
                                "fuzz.httpfuzzer.messagetype.result.originalMessage"),
                        originalMessage));
    }

    @Override
    protected HttpFuzzerTask createFuzzerTask(
            long taskId, HttpMessage message, List<Object> payloads) {
        return new HttpFuzzerTask(taskId, this, message, payloads);
    }

    @Override
    protected HttpFuzzerOptions getFuzzerOptions() {
        return (HttpFuzzerOptions) super.getFuzzerOptions();
    }

    protected HttpSender getHttpSender() {
        return httpSender;
    }

    protected Session getCurrentSession() {
        return currentSession;
    }

    protected void fuzzResultAvailable(HttpFuzzResult result) {
        messagesModel.addResult(result);
    }

    public HttpFuzzerResultsTableModel getMessagesModel() {
        return messagesModel;
    }

    public HttpFuzzerErrorsTableModel getErrorsModel() {
        return errorsModel;
    }

    // Overridden to expose the method to HttpFuzzerTask
    @Override
    protected void increaseErrorCount(long taskId, String source, String reason) {
        super.increaseErrorCount(taskId, source, reason);
    }

    @Override
    protected void handleError(
            long taskId,
            String source,
            String reason,
            int totalErrors,
            boolean maxErrorsReached,
            Collection<MessageLocationReplacement<?>> replacements) {
        for (HttpFuzzerListener listener : listeners) {
            listener.errorFound(totalErrors);
        }
        errorsModel.addFuzzerError(taskId, source, reason);
        if (maxErrorsReached) {
            errorsModel.addFuzzerError(
                    taskId,
                    Constant.messages.getString("fuzz.httpfuzzer.results.error.source.httpfuzzer"),
                    Constant.messages.getString(
                            "fuzz.httpfuzzer.results.error.message.maxErrorsReached"));
        }
    }

    protected void preProcessMessage(long taskId, HttpMessage message, List<Object> payloads) {
        if (messageProcessors.isEmpty()) {
            return;
        }

        synchronized (messageProcessors) {
            HttpFuzzerTaskProcessorUtils utils =
                    new HttpFuzzerTaskProcessorUtils(this, originalMessage, taskId, payloads);
            for (Iterator<HttpFuzzerMessageProcessor> it = messageProcessors.iterator();
                    it.hasNext(); ) {
                HttpFuzzerMessageProcessor messageProcessor = it.next();
                try {
                    utils.setCurrentProcessorName(messageProcessor.getName());
                    messageProcessor.processMessage(utils, message);
                    Stats.incCounter(ExtensionFuzz.HTTP_MSG_PROCESSOR_RUN_STATS);
                } catch (ProcessingException e) {
                    Stats.incCounter(ExtensionFuzz.HTTP_MSG_PROCESSOR_ERROR_STATS);
                    errorsModel.addFuzzerError(
                            taskId,
                            Constant.messages.getString(
                                    "fuzz.httpfuzzer.results.error.source.httpfuzzer"),
                            Constant.messages.getString(
                                    "fuzz.httpfuzzer.results.error.message.removedProcessorOnError",
                                    messageProcessor.getName()));
                    logger.warn(
                            "Error while executing a processor, it will not be called again:", e);
                    it.remove();
                }
            }
        }
    }

    protected void messageSent(long taskId, HttpMessage message) {
        int total = messagesSentCounter.incrementAndGet();
        for (HttpFuzzerListener listener : listeners) {
            listener.messageSent(total);
        }
    }

    protected boolean processResult(long taskId, HttpFuzzResult result) {
        if (messageProcessors.isEmpty()) {
            return true;
        }

        synchronized (messageProcessors) {
            HttpFuzzerTaskProcessorUtils utils =
                    new HttpFuzzerTaskProcessorUtils(
                            this,
                            originalMessage,
                            taskId,
                            result.getPayloads(),
                            result,
                            getExtensionAlert());
            for (Iterator<HttpFuzzerMessageProcessor> it = messageProcessors.iterator();
                    it.hasNext(); ) {
                HttpFuzzerMessageProcessor messageProcessor = it.next();
                try {
                    utils.setCurrentProcessorName(messageProcessor.getName());
                    if (!messageProcessor.processResult(utils, result)) {
                        // Discard the result.
                        return false;
                    }
                } catch (ProcessingException e) {
                    errorsModel.addFuzzerError(
                            taskId,
                            Constant.messages.getString(
                                    "fuzz.httpfuzzer.results.error.source.httpfuzzer"),
                            Constant.messages.getString(
                                    "fuzz.httpfuzzer.results.error.message.removedProcessorOnError",
                                    messageProcessor.getName()));
                    logger.warn(
                            "Error while executing a processor, it will not be called again:", e);
                    it.remove();
                }
            }
        }
        return true;
    }

    private static ExtensionAlert getExtensionAlert() {
        return Control.getSingleton().getExtensionLoader().getExtension(ExtensionAlert.class);
    }

    public int getMessagesSentCount() {
        return messagesSentCounter.get();
    }

    public void addHttpFuzzerListener(HttpFuzzerListener listener) {
        listeners.add(listener);
    }

    public void removeHttpFuzzerListener(HttpFuzzerListener listener) {
        listeners.remove(listener);
    }

    public List<SearchResult> search(Pattern pattern, boolean inverse) {
        return messagesModel.search(pattern, inverse);
    }

    public List<SearchResult> search(Pattern pattern, boolean inverse, int max) {
        return messagesModel.search(pattern, inverse, max);
    }
}
