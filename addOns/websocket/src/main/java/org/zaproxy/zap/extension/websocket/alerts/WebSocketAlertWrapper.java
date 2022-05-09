/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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
package org.zaproxy.zap.extension.websocket.alerts;

import java.util.ArrayList;
import java.util.Objects;
import org.apache.commons.lang.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.websocket.WebSocketMessageDTO;
import org.zaproxy.zap.extension.websocket.utility.InvalidUtf8Exception;

/** Wrapper for Alerts. This wrapper used to construct alerts for WebSocket */
public class WebSocketAlertWrapper {

    private static final Logger LOGGER = LogManager.getLogger(WebSocketAlertWrapper.class);

    private Alert alert;

    private WebSocketMessageDTO webSocketMessageDTO;

    /**
     * Initialize a new {@link Alert}.
     *
     * @see {@link Alert#Alert(int, int, int, String)}
     */
    private WebSocketAlertWrapper(WebSocketMessageDTO webSocketMessageDTO, Alert alert) {
        this.alert = alert;
        this.webSocketMessageDTO = webSocketMessageDTO;
    }

    public Alert getAlert() {
        return alert;
    }

    public String getDescription() {
        return alert.getDescription();
    }

    public String getHandshakeUri() {
        return alert.getUri();
    }

    public String getParam() {
        return alert.getParam();
    }

    public String getAttack() {
        return alert.getAttack();
    }

    public WebSocketMessageDTO getWebSocketMessageDTO() {
        return webSocketMessageDTO;
    }

    public String getSolution() {
        return alert.getSolution();
    }

    public String getReference() {
        return alert.getReference();
    }

    public String getEvidence() {
        return alert.getReference();
    }

    public int getCweId() {
        return alert.getCweId();
    }

    public int getWascId() {
        return alert.getWascId();
    }

    public HttpMessage getHandshakeMessage() {
        return alert.getMessage();
    }

    public Alert.Source getSource() {
        return alert.getSource();
    }

    public HistoryReference getHandshakeReference() {
        return alert.getHistoryRef();
    }

    public int getAlertId() {
        return alert.getAlertId();
    }

    public int getConfidence() {
        return alert.getConfidence();
    }

    public int getRisk() {
        return alert.getRisk();
    }

    public String getName() {
        return alert.getName();
    }

    public String getMessageReadablePayload() {
        try {
            return webSocketMessageDTO.getReadablePayload();
        } catch (InvalidUtf8Exception e) {
            return Constant.messages.getString("websocket.payload.invalid_utf8");
        }
    }

    public abstract static class WebSocketAlertBuilder {

        private Alert.Source source = null;
        private String name = "";
        private String description = "";
        private String param = "";
        private String attack = "";
        private HttpMessage handshakeMessage = null;
        private String uri = "";
        private String otherInfo = "";
        private String solution = "";
        private String reference = "";
        private String evidence = "";
        private int cweId = 0;
        private int wascId = 0;
        private int pluginId = -1;
        private int risk = Alert.RISK_LOW;
        private int confidence = Alert.CONFIDENCE_MEDIUM;

        private static final String OTHER_INFO_LABEL = "[WebSocket Message] ";

        private WebSocketMessageDTO webSocketMessageDTO = null;

        protected WebSocketAlertBuilder setSource(Alert.Source source) {
            this.source = source;
            return this;
        }

        public WebSocketAlertBuilder setPluginId(int pluginId) {
            this.pluginId = pluginId;
            return this;
        }

        /** @throws NullPointerException If name is null */
        public WebSocketAlertBuilder setName(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }

        public WebSocketAlertBuilder setDescription(String description) {
            this.description = description;
            return this;
        }

        public WebSocketAlertBuilder setParam(String param) {
            this.param = param;
            return this;
        }

        public WebSocketAlertBuilder setAttack(String attack) {
            this.attack = attack;
            return this;
        }

        protected WebSocketAlertBuilder setMessage(WebSocketMessageDTO webSocketMessageDTO) {
            if (webSocketMessageDTO == null) {
                // Can be null when generating example alerts
                return this;
            }

            HttpMessage handshakeMessage;

            try {
                handshakeMessage =
                        webSocketMessageDTO.getChannel().getHandshakeReference().getHttpMessage();
            } catch (Exception e) {
                LOGGER.info(
                        "Couldn't get the Handshake HTTP Message for this specific channel. Channel ID: {}",
                        webSocketMessageDTO.getChannel().getId(),
                        e);
                return this;
            }

            this.handshakeMessage = handshakeMessage;
            this.uri = handshakeMessage.getRequestHeader().getURI().toString();

            this.webSocketMessageDTO = webSocketMessageDTO;
            try {
                this.otherInfo = OTHER_INFO_LABEL + webSocketMessageDTO.getReadablePayload();
            } catch (InvalidUtf8Exception e) {
                this.otherInfo =
                        OTHER_INFO_LABEL
                                + Constant.messages.getString("websocket.payload.invalid_utf8");
            }
            return this;
        }

        public WebSocketAlertBuilder setSolution(String solution) {
            this.solution = solution;
            return this;
        }

        public WebSocketAlertBuilder setReference(String reference) {
            this.reference = reference;
            return this;
        }

        public WebSocketAlertBuilder setEvidence(String evidence) {
            this.evidence = evidence;
            return this;
        }

        public WebSocketAlertBuilder setCweId(int cweId) {
            this.cweId = cweId;
            return this;
        }

        public WebSocketAlertBuilder setWascId(int wascId) {
            this.wascId = wascId;
            return this;
        }

        public WebSocketAlertBuilder setRiskConfidence(int risk, int confidence) {
            this.risk = risk;
            this.confidence = confidence;
            return this;
        }

        /** @throws IllegalStateException If Plugin ID, Alert Source or Name have not been set. */
        public WebSocketAlertWrapper build() {

            if (pluginId != -1 && source != null && !name.isEmpty()) {

                Alert alert = new Alert(pluginId, risk, confidence, name);
                alert.setSource(source);
                alert.setDetail(
                        description,
                        uri,
                        param,
                        attack,
                        otherInfo,
                        solution,
                        reference,
                        evidence,
                        cweId,
                        wascId,
                        handshakeMessage);
                return new WebSocketAlertWrapper(webSocketMessageDTO, alert);
            }
            StringBuilder exceptionMsg =
                    new StringBuilder("Alert can't be built. Missing values for: {");
            ArrayList<String> missingValues = new ArrayList<>();

            if (pluginId == -1) missingValues.add("Plugin ID");
            if (source == null) missingValues.add("Alert Source");
            if (name.isEmpty()) missingValues.add("Alert Name");
            exceptionMsg.append(StringUtils.join(missingValues, ", ")).append("}");
            throw new IllegalStateException(exceptionMsg.toString());
        }

        protected abstract WebSocketAlertWrapper raise();
    }
}
