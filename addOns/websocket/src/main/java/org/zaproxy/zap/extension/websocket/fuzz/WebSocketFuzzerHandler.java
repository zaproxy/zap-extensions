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
import java.util.List;
import java.util.Map;
import java.util.SortedSet;
import java.util.TreeSet;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.fuzz.FuzzerHandler;
import org.zaproxy.zap.extension.fuzz.FuzzerOptions;
import org.zaproxy.zap.extension.fuzz.impl.FuzzerDialog;
import org.zaproxy.zap.extension.fuzz.messagelocations.MessageLocationReplacement;
import org.zaproxy.zap.extension.fuzz.messagelocations.MessageLocationReplacementGenerator;
import org.zaproxy.zap.extension.fuzz.messagelocations.MessageLocationReplacer;
import org.zaproxy.zap.extension.fuzz.messagelocations.MessageLocationReplacers;
import org.zaproxy.zap.extension.fuzz.messagelocations.MessageLocationsReplacementStrategy;
import org.zaproxy.zap.extension.fuzz.messagelocations.MultipleMessageLocationsBreadthFirstReplacer;
import org.zaproxy.zap.extension.fuzz.messagelocations.MultipleMessageLocationsDepthFirstReplacer;
import org.zaproxy.zap.extension.fuzz.messagelocations.MultipleMessageLocationsReplacer;
import org.zaproxy.zap.extension.fuzz.payloads.PayloadGeneratorMessageLocation;
import org.zaproxy.zap.extension.websocket.ExtensionWebSocket;
import org.zaproxy.zap.extension.websocket.WebSocketMessageDTO;
import org.zaproxy.zap.extension.websocket.WebSocketProxy;
import org.zaproxy.zap.extension.websocket.fuzz.ui.WebSocketFuzzResultsContentPanel;
import org.zaproxy.zap.extension.websocket.fuzz.ui.WebSocketMessageSelectorPanel;
import org.zaproxy.zap.extension.websocket.messagelocations.WebSocketMessageLocation;
import org.zaproxy.zap.extension.websocket.ui.httppanel.SingleWebSocketMessageContainer;
import org.zaproxy.zap.extension.websocket.ui.httppanel.WebSocketMessageContainer;
import org.zaproxy.zap.view.messagecontainer.MessageContainer;
import org.zaproxy.zap.view.messagecontainer.SelectableContentMessageContainer;

public class WebSocketFuzzerHandler implements FuzzerHandler<WebSocketMessageDTO, WebSocketFuzzer> {

    private WebSocketFuzzResultsContentPanel websocketFuzzResultsContentPanel;

    private final List<WebSocketFuzzerMessageProcessorUIHandler<WebSocketFuzzerMessageProcessor, ?>>
            messageProcessors;

    public WebSocketFuzzerHandler() {
        this.messageProcessors = new ArrayList<>();
    }

    @Override
    public Class<WebSocketFuzzer> getFuzzerClass() {
        return WebSocketFuzzer.class;
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString("websocket.fuzzer.messagetype");
    }

    @Override
    public WebSocketMessageSelectorPanel createMessageSelectorPanel() {
        return new WebSocketMessageSelectorPanel();
    }

    @Override
    public WebSocketFuzzer showFuzzerDialog(
            MessageContainer<WebSocketMessageDTO> messageContainer, FuzzerOptions defaultOptions) {
        if (!canFuzz(messageContainer)) {
            return null;
        }
        WebSocketMessageDTO message = extractMessage((WebSocketMessageContainer) messageContainer);
        if (message != null) {
            return showFuzzerDialogImpl(message, null, defaultOptions);
        }
        return null;
    }

    @Override
    public WebSocketFuzzer showFuzzerDialog(
            SelectableContentMessageContainer<WebSocketMessageDTO> messageContainer,
            FuzzerOptions defaultOptions) {
        if (!canFuzz(messageContainer)) {
            return null;
        }

        WebSocketMessageDTO message = extractMessage((WebSocketMessageContainer) messageContainer);
        if (message != null) {
            return showFuzzerDialogImpl(message, messageContainer, defaultOptions);
        }
        return null;
    }

    @Override
    public WebSocketFuzzer showFuzzerDialog(
            WebSocketMessageDTO message, FuzzerOptions defaultOptions) {
        return showFuzzerDialogImpl(message, null, defaultOptions);
    }

    private WebSocketFuzzer showFuzzerDialogImpl(
            WebSocketMessageDTO message,
            SelectableContentMessageContainer<WebSocketMessageDTO> container,
            FuzzerOptions defaultOptions) {
        FuzzerDialog<WebSocketMessageDTO, FuzzerOptions, WebSocketFuzzerMessageProcessor>
                fuzzDialogue =
                        new FuzzerDialog<>(
                                View.getSingleton().getMainFrame(),
                                defaultOptions,
                                message,
                                message.isOutgoing(),
                                new WebSocketFuzzerHandlerOptionsPanel(),
                                new WebSocketFuzzerMessageProcessorCollection(
                                        message, messageProcessors));

        if (container != null) {
            if (fuzzDialogue.setSelectedContainer(container.getName())) {
                fuzzDialogue.addMessageLocation(container.getSelection());
            }
        }

        fuzzDialogue.setVisible(true);
        fuzzDialogue.dispose();

        return createFuzzer(
                message,
                fuzzDialogue.getFuzzLocations(),
                fuzzDialogue.getFuzzerOptions(),
                fuzzDialogue.getFuzzerMessageProcessors());
    }

    @SuppressWarnings("unchecked")
    private WebSocketFuzzer createFuzzer(
            WebSocketMessageDTO message,
            List<PayloadGeneratorMessageLocation<?>> fuzzLocations,
            FuzzerOptions options,
            List<WebSocketFuzzerMessageProcessor> processors) {
        if (fuzzLocations.isEmpty()) {
            return null;
        }

        MessageLocationReplacer<WebSocketMessageDTO> replacer =
                MessageLocationReplacers.getInstance()
                        .getMLR(WebSocketMessageDTO.class, WebSocketMessageLocation.class);

        replacer.init(message);

        MultipleMessageLocationsReplacer<WebSocketMessageDTO> multipleMessageLocationsReplacer;
        if (MessageLocationsReplacementStrategy.DEPTH_FIRST
                == options.getPayloadsReplacementStrategy()) {
            multipleMessageLocationsReplacer = new MultipleMessageLocationsDepthFirstReplacer<>();
        } else {
            multipleMessageLocationsReplacer = new MultipleMessageLocationsBreadthFirstReplacer<>();
        }
        SortedSet<MessageLocationReplacementGenerator<?, ?>> messageLocationReplacementGenerators =
                new TreeSet<>();

        for (PayloadGeneratorMessageLocation<?> fuzzLocation : fuzzLocations) {
            messageLocationReplacementGenerators.add(fuzzLocation);
        }
        multipleMessageLocationsReplacer.init(replacer, messageLocationReplacementGenerators);

        ExtensionWebSocket extensionWebSocket =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionWebSocket.class);

        return new WebSocketFuzzer(
                extensionWebSocket.getStorage().getTable(),
                createFuzzerName(message),
                options,
                getConnectedProxies(),
                message,
                (List<MessageLocationReplacementGenerator<?, MessageLocationReplacement<?>>>)
                        (ArrayList) fuzzLocations,
                multipleMessageLocationsReplacer,
                processors);
    }

    private String createFuzzerName(WebSocketMessageDTO message) {
        StringBuilder strBuilder = new StringBuilder();
        strBuilder
                .append(message.getChannel().getHost())
                .append(" #")
                .append(message.getChannel().getId());
        if (strBuilder.length() > 30) {
            strBuilder.setLength(27);
            strBuilder.append("...");
        }
        return Constant.messages.getString(
                "websocket.fuzzer.fuzzerNamePrefix", strBuilder.toString());
    }

    @Override
    public WebSocketFuzzResultsContentPanel getResultsContentPanel() {
        return getWebSocketFuzzResultsContentPanel();
    }

    protected WebSocketFuzzResultsContentPanel getWebSocketFuzzResultsContentPanel() {
        if (websocketFuzzResultsContentPanel == null) {
            websocketFuzzResultsContentPanel = new WebSocketFuzzResultsContentPanel();
        }
        return websocketFuzzResultsContentPanel;
    }

    @Override
    public boolean canHandle(MessageContainer<?> messageContainer) {
        if (WebSocketMessageDTO.class.isAssignableFrom(messageContainer.getMessageClass())) {
            return true;
        }
        return false;
    }

    @Override
    public boolean canFuzz(MessageContainer<?> messageContainer) {
        if (messageContainer.isEmpty() || !canHandle(messageContainer)) {
            return false;
        }

        if (!(messageContainer instanceof WebSocketMessageContainer)) {
            return false;
        }

        return extractMessage((WebSocketMessageContainer) messageContainer) != null;
    }

    private static WebSocketMessageDTO extractMessage(WebSocketMessageContainer messageContainer) {
        if (messageContainer instanceof SingleWebSocketMessageContainer) {
            return ((SingleWebSocketMessageContainer) messageContainer).getMessage();
        }
        return null;
    }

    @Override
    public void scannerRemoved(WebSocketFuzzer fuzzer) {
        getWebSocketFuzzResultsContentPanel().clear(fuzzer);
    }

    @Override
    public WebSocketMessageDTO getMessage(MessageContainer<WebSocketMessageDTO> messageContainer) {
        return extractMessage((WebSocketMessageContainer) messageContainer);
    }

    @SuppressWarnings("unchecked")
    protected <
                    T1 extends WebSocketFuzzerMessageProcessor,
                    T2 extends WebSocketFuzzerMessageProcessorUI<T1>>
            void addFuzzerMessageProcessorUIHandler(
                    WebSocketFuzzerMessageProcessorUIHandler<T1, T2> processorUIHandler) {
        messageProcessors.add(
                (WebSocketFuzzerMessageProcessorUIHandler<WebSocketFuzzerMessageProcessor, ?>)
                        processorUIHandler);
    }

    protected <
                    T1 extends WebSocketFuzzerMessageProcessor,
                    T2 extends WebSocketFuzzerMessageProcessorUI<T1>>
            void removeFuzzerMessageProcessorUIHandler(
                    WebSocketFuzzerMessageProcessorUIHandler<T1, T2> processorUIHandler) {
        messageProcessors.remove(processorUIHandler);
    }

    private static Map<Integer, WebSocketProxy> getConnectedProxies() {
        return Control.getSingleton()
                .getExtensionLoader()
                .getExtension(ExtensionWebSocketFuzzer.class)
                .getConnectedProxies();
    }
}
