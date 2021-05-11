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
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.alert.ExtensionAlert;

public class HttpFuzzerTaskProcessorUtils {

    private static final Logger LOGGER = LogManager.getLogger(HttpFuzzerTaskProcessorUtils.class);

    private static final int PLUGIN_ID = 50002;

    private final HttpFuzzer httpFuzzer;
    private final HttpMessage originalMessage;
    private final long taskId;
    private final List<Object> payloads;
    private final HttpFuzzResult fuzzResult;
    private final ExtensionAlert extensionAlert;
    private HistoryReference historyReference;
    private String processorName;
    private Map<String, String> parameters;

    protected HttpFuzzerTaskProcessorUtils(
            HttpFuzzer httpFuzzer,
            HttpMessage originalMessage,
            long taskId,
            List<Object> payloads) {
        this(httpFuzzer, originalMessage, taskId, payloads, null, null);
    }

    protected HttpFuzzerTaskProcessorUtils(
            HttpFuzzer httpFuzzer,
            HttpMessage originalMessage,
            long taskId,
            List<Object> payloads,
            HttpFuzzResult fuzzResult,
            ExtensionAlert extensionAlert) {
        this.httpFuzzer = httpFuzzer;
        this.originalMessage = originalMessage;
        this.taskId = taskId;
        this.payloads = payloads;
        this.fuzzResult = fuzzResult;
        this.extensionAlert = extensionAlert;
    }

    protected void setCurrentProcessorName(String name) {
        processorName = name;
    }

    public HttpMessage getOriginalMessage() {
        return originalMessage;
    }

    public void raiseAlert(int risk, int confidence, String name, String description) {
        raiseAlert(risk, confidence, name, description, null, null, null, null, null, null, 0, 0);
    }

    public void raiseAlert(
            int risk,
            int confidence,
            String name,
            String description,
            String param,
            String attack,
            String otherInfo,
            String solution,
            String reference,
            String evidence,
            int cweId,
            int wascId) {
        if (fuzzResult == null) {
            return;
        }

        if (extensionAlert != null) {
            Alert alert =
                    Alert.builder()
                            .setPluginId(PLUGIN_ID)
                            .setRisk(risk)
                            .setConfidence(confidence)
                            .setName(name)
                            .setDescription(description)
                            .setParam(param)
                            .setAttack(attack)
                            .setOtherInfo(otherInfo)
                            .setSolution(solution)
                            .setReference(reference)
                            .setEvidence(evidence)
                            .setCweId(cweId)
                            .setWascId(wascId)
                            .setMessage(fuzzResult.getHttpMessage())
                            .build();

            if (historyReference == null) {
                try {
                    historyReference =
                            new HistoryReference(
                                    Model.getSingleton().getSession(),
                                    HistoryReference.TYPE_FUZZER,
                                    fuzzResult.getHttpMessage());
                } catch (HttpMalformedHeaderException | DatabaseException e) {
                    httpFuzzer.increaseErrorCount(
                            taskId,
                            processorName,
                            Constant.messages.getString(
                                    "fuzz.httpfuzzer.processor.scriptProcessor.error.persistMessageForAlert"));
                    LOGGER.warn("Failed to persist the message and raise the alert:", e);
                    return;
                }
            }
            fuzzResult.getHttpMessage().setHistoryRef(historyReference);
            extensionAlert.alertFound(alert, historyReference);
        }
    }

    public void stopFuzzer() {
        httpFuzzer.stopScan();
    }

    public List<Object> getPayloads() {
        return payloads;
    }

    /** @deprecated (2.0.0) Use {@link #getPayloads()} instead. */
    @Deprecated
    @SuppressWarnings("javadoc")
    public List<Object> getPaylaods() {
        return payloads;
    }

    public void increaseErrorCount(String reason) {
        httpFuzzer.increaseErrorCount(taskId, processorName, reason);
    }

    public boolean sendMessage(HttpMessage message) {
        return sendMessage(message, true);
    }

    public boolean sendMessage(HttpMessage message, boolean followRedirects) {
        try {
            httpFuzzer.getHttpSender().sendAndReceive(message, followRedirects);
            httpFuzzer.messageSent(taskId, message);
            return true;
        } catch (IOException e) {
            LOGGER.warn("Failed to send a message:", e);
            return false;
        }
    }

    public void addMessageToResults(String type, HttpMessage httpMessage) {
        addMessageToResults(type, httpMessage, null, null);
    }

    public void addMessageToResults(
            String type, HttpMessage httpMessage, String customStateKey, Object customState) {
        HttpFuzzResult result = new HttpFuzzResult(taskId, type, httpMessage);
        if (customStateKey != null) {
            result.addCustomState(customStateKey, customState);
        }
        httpFuzzer.fuzzResultAvailable(result);
    }

    public Map<String, String> getParameters() {
        return parameters;
    }

    public void setParameters(Map<String, String> paramsMap) {
        this.parameters = paramsMap;
    }
}
