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

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.websocket.WebSocketMessageDTO;
import org.zaproxy.zap.extension.websocket.utility.InvalidUtf8Exception;

/** Wrapper for Alerts. This wrapper used to construct alerts for WebSocket */
public class WebSocketAlertWrapper {

    private static final Logger LOGGER = Logger.getLogger(WebSocketAlertWrapper.class);

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

        private Alert alert;

        private static final String OTHER_INFO_LABEL = "[WebSocket Message] ";

        private WebSocketMessageDTO webSocketMessageDTO;

        public WebSocketAlertBuilder(int pluginId, Alert.Source source) {
            alert = new Alert(pluginId);
            alert.setSource(source);
        }

        public WebSocketAlertBuilder setName(String name) {
            alert.setName(name);
            return this;
        }

        public WebSocketAlertBuilder setDescription(String description) {
            alert.setDescription(description);
            return this;
        }

        public WebSocketAlertBuilder setParam(String param) {
            alert.setParam(param);
            return this;
        }

        public WebSocketAlertBuilder setAttack(String attack) {
            alert.setAttack(attack);
            return this;
        }

        protected WebSocketAlertBuilder setMessage(WebSocketMessageDTO webSocketMessageDTO) {

            HttpMessage handshakeMessage;

            try {
                handshakeMessage =
                        webSocketMessageDTO.channel.getHandshakeReference().getHttpMessage();
            } catch (Exception e) {
                LOGGER.info(
                        "Couldn't get the Handshake Http Message for this specific channel. "
                                + "Channel ID:"
                                + webSocketMessageDTO.channel.id,
                        e);
                return this;
            }

            alert.setMessage(handshakeMessage);
            alert.setUri(handshakeMessage.getRequestHeader().getURI().toString());

            this.webSocketMessageDTO = webSocketMessageDTO;
            try {
                alert.setOtherInfo(OTHER_INFO_LABEL + webSocketMessageDTO.getReadablePayload());
            } catch (InvalidUtf8Exception e) {
                alert.setOtherInfo(
                        OTHER_INFO_LABEL
                                + Constant.messages.getString("websocket.payload.invalid_utf8"));
            }
            return this;
        }

        public WebSocketAlertBuilder setSolution(String solution) {
            alert.setSolution(solution);
            return this;
        }

        public WebSocketAlertBuilder setReference(String reference) {
            alert.setReference(reference);
            return this;
        }

        public WebSocketAlertBuilder setEvidence(String evidence) {
            alert.setEvidence(evidence);
            return this;
        }

        public WebSocketAlertBuilder setCweId(int cweId) {
            alert.setCweId(cweId);
            return this;
        }

        public WebSocketAlertBuilder setWascId(int wascId) {
            alert.setWascId(wascId);
            return this;
        }

        public WebSocketAlertBuilder setRiskConfidence(int risk, int confidence) {
            alert.setRiskConfidence(risk, confidence);
            return this;
        }

        public WebSocketAlertWrapper build() {
            return new WebSocketAlertWrapper(webSocketMessageDTO, alert);
        }

        protected abstract WebSocketAlertWrapper raise();
    }
}
