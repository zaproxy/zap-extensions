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
package org.zaproxy.zap.extension.websocket.fuzz;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.zaproxy.zap.extension.fuzz.AbstractFuzzer;
import org.zaproxy.zap.extension.fuzz.FuzzerOptions;
import org.zaproxy.zap.extension.fuzz.messagelocations.MessageLocationReplacement;
import org.zaproxy.zap.extension.fuzz.messagelocations.MessageLocationReplacementGenerator;
import org.zaproxy.zap.extension.fuzz.messagelocations.MultipleMessageLocationsReplacer;
import org.zaproxy.zap.extension.websocket.WebSocketMessageDTO;
import org.zaproxy.zap.extension.websocket.WebSocketProxy;
import org.zaproxy.zap.extension.websocket.db.TableWebSocket;
import org.zaproxy.zap.extension.websocket.fuzz.ui.WebSocketFuzzMessagesViewModel;

public class WebSocketFuzzer extends AbstractFuzzer<WebSocketMessageDTO> {

    private static final AtomicInteger FUZZ_ID_GENERATOR = new AtomicInteger(0);

    private final Session currentSession;
    private final Map<Integer, WebSocketProxy> wsProxies;
    private final WebSocketFuzzMessagesViewModel messagesModel;
    private final List<WebSocketFuzzerListener> listeners;
    private final List<WebSocketFuzzerMessageProcessor> messageProcessors;
    private final AtomicInteger messagesSentCounter;
    private final WebSocketMessageDTO originalMessage;
    private final int id;

    public WebSocketFuzzer(
            TableWebSocket table,
            String fuzzerScanName,
            FuzzerOptions fuzzerOptions,
            Map<Integer, WebSocketProxy> wsProxies,
            WebSocketMessageDTO message,
            List<MessageLocationReplacementGenerator<?, MessageLocationReplacement<?>>>
                    fuzzLocations,
            MultipleMessageLocationsReplacer<WebSocketMessageDTO> multipleMessageLocationsReplacer,
            List<WebSocketFuzzerMessageProcessor> messageProcessors) {
        super(
                fuzzerScanName,
                fuzzerOptions,
                message,
                fuzzLocations,
                multipleMessageLocationsReplacer);

        this.id = FUZZ_ID_GENERATOR.incrementAndGet();
        this.wsProxies = wsProxies;
        this.messageProcessors =
                messageProcessors.isEmpty()
                        ? Collections.<WebSocketFuzzerMessageProcessor>emptyList()
                        : Collections.synchronizedList(new ArrayList<>(messageProcessors));
        currentSession = Model.getSingleton().getSession();

        this.originalMessage = message;

        messagesModel = new WebSocketFuzzMessagesViewModel(id, table);
        listeners = new ArrayList<>(1);
        messagesSentCounter = new AtomicInteger(0);
    }

    @Override
    protected WebSocketFuzzerTask createFuzzerTask(
            long taskId, WebSocketMessageDTO message, List<Object> payloads) {
        return new WebSocketFuzzerTask(taskId, this, message, payloads);
    }

    protected Map<Integer, WebSocketProxy> getWebSocketProxies() {
        return wsProxies;
    }

    protected Session getCurrentSession() {
        return currentSession;
    }

    protected void fuzzResultAvailable(WebSocketFuzzResult result) {
        messagesModel.addResult(
                result, messagesSentCounter.get(), getMessagesSentCount() >= getMaximum());
    }

    public WebSocketFuzzMessagesViewModel getMessagesModel() {
        return messagesModel;
    }

    public int getId() {
        return id;
    }

    // Overridden to expose the method to WebSocketFuzzerTask
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
        for (WebSocketFuzzerListener listener : listeners) {
            listener.errorFound(totalErrors);
        }
    }

    protected void preProcessMessage(
            long taskId, WebSocketMessageDTO message, List<Object> payloads) {
        if (messageProcessors.isEmpty()) {
            return;
        }

        synchronized (messageProcessors) {
            WebSocketFuzzerTaskProcessorUtils utils =
                    new WebSocketFuzzerTaskProcessorUtils(this, originalMessage, taskId, payloads);
            for (Iterator<WebSocketFuzzerMessageProcessor> it = messageProcessors.iterator();
                    it.hasNext(); ) {
                WebSocketFuzzerMessageProcessor messageProcessor = it.next();
                try {
                    utils.setCurrentProcessorName(messageProcessor.getName());
                    messageProcessor.processMessage(utils, message);
                } catch (ProcessingException e) {
                    logger.warn(
                            "Error while executing a processor, it will not be called again:", e);
                    it.remove();
                }
            }
        }
    }

    protected void messageSent(long taskId, WebSocketMessageDTO message) {
        int total = messagesSentCounter.incrementAndGet();
        for (WebSocketFuzzerListener listener : listeners) {
            listener.messageSent(total);
        }
    }

    public int getMessagesSentCount() {
        return messagesSentCounter.get();
    }

    public void addWebSocketFuzzerListener(WebSocketFuzzerListener listener) {
        listeners.add(listener);
    }

    public void removeWebSocketFuzzerListener(WebSocketFuzzerListener listener) {
        listeners.remove(listener);
    }
}
