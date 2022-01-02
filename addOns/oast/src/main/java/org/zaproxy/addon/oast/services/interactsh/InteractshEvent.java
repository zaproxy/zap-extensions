/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.addon.oast.services.interactsh;

import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Objects;
import net.sf.json.JSONObject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.network.HttpBody;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.zaproxy.addon.oast.OastRequest;
import org.zaproxy.zap.network.HttpRequestBody;
import org.zaproxy.zap.network.HttpResponseBody;

public class InteractshEvent {

    public static final Logger LOGGER = LogManager.getLogger(InteractshEvent.class);
    static final String EMAIL_FROM_HEADER = "Email-From";

    private final String protocol;
    private final String uniqueId;
    private final String fullId;
    private final String rawRequest;
    private final String rawResponse;
    private final String remoteAddress;
    private final Instant timestamp;
    private final String queryType;
    private final String smtpFrom;

    public InteractshEvent(
            String protocol,
            String uniqueId,
            String fullId,
            String rawRequest,
            String rawResponse,
            String remoteAddress,
            String timestamp,
            String queryType,
            String smtpFrom) {
        this.protocol = protocol;
        this.uniqueId = uniqueId;
        this.fullId = fullId;
        this.rawRequest = rawRequest;
        this.rawResponse = rawResponse;
        this.remoteAddress = remoteAddress;
        this.timestamp = Instant.from(DateTimeFormatter.ISO_OFFSET_DATE_TIME.parse(timestamp));
        this.queryType = queryType;
        this.smtpFrom = smtpFrom;
    }

    public String getTimestamp() {
        return timestamp.toString();
    }

    public String getProtocol() {
        return protocol;
    }

    public String getRemoteAddress() {
        return remoteAddress;
    }

    public String getUniqueId() {
        return uniqueId;
    }

    public InteractshEvent(JSONObject event) {
        this(
                event.getString("protocol"),
                event.getString("unique-id"),
                event.getString("full-id"),
                event.getString("raw-request"),
                event.optString("raw-response"),
                event.optString("remote-address"),
                event.getString("timestamp"),
                event.optString("q-type"),
                event.optString("smtp-from"));
    }

    public OastRequest toOastRequest() throws HttpMalformedHeaderException, DatabaseException {
        HttpMessage msg =
                new HttpMessage(
                        new HttpRequestHeader(),
                        new HttpRequestBody(),
                        new HttpResponseHeader(),
                        new HttpResponseBody());
        msg.setTimeSentMillis(timestamp.toEpochMilli());
        if ("http".equals(protocol)) {
            extractAndSetMsg(msg.getRequestHeader(), msg.getRequestBody(), rawRequest);
            extractAndSetMsg(msg.getResponseHeader(), msg.getResponseBody(), rawResponse);
        } else if ("dns".equals(protocol)) {
            String searchString = "QUESTION SECTION:\n;";
            int requestUriIndex = rawRequest.indexOf(searchString) + searchString.length();
            String requestUri =
                    rawRequest.substring(
                            requestUriIndex, rawRequest.indexOf("\t", requestUriIndex));
            if (!requestUri.contains("://")) {
                requestUri = "http://" + requestUri;
            }
            String method = "DNS" + (queryType.isEmpty() ? "" : "_" + queryType);
            String requestHeader = method + " " + requestUri + " HTTP/1.1\r\n\r\n";
            msg.setRequestHeader(requestHeader);
            msg.setRequestBody(rawRequest);
            msg.setResponseHeader("HTTP/1.1 200 OK\r\n");
            msg.setResponseBody(rawResponse);
        } else if ("smtp".equals(protocol)) {
            String requestHeader = "SMTP https://interact.sh HTTP/1.1\r\n\r\n";
            msg.setRequestHeader(requestHeader);
            msg.getRequestHeader().setHeader(EMAIL_FROM_HEADER, smtpFrom);
            msg.setRequestBody(rawRequest);
        }
        return OastRequest.create(msg, remoteAddress, "Interactsh");
    }

    private void extractAndSetMsg(HttpHeader header, HttpBody body, String rawMsg) {
        try {
            int separatorIndex = rawMsg.indexOf("\r\n\r\n") + 4;
            // TODO: Do not replace HTTP/2.0 with HTTP/1.1
            String headerString =
                    rawMsg.substring(0, separatorIndex).replace("HTTP/2.0", "HTTP/1.1");
            String bodyString = rawMsg.substring(separatorIndex);
            header.setMessage(headerString);
            body.setBody(bodyString);
        } catch (HttpMalformedHeaderException e) {
            body.setBody(rawMsg);
            LOGGER.warn("Bad Interactsh message dump: {}.", rawMsg);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        InteractshEvent that = (InteractshEvent) o;
        return protocol.equals(that.protocol)
                && uniqueId.equals(that.uniqueId)
                && fullId.equals(that.fullId)
                && rawRequest.equals(that.rawRequest)
                && rawResponse.equals(that.rawResponse)
                && remoteAddress.equals(that.remoteAddress)
                && timestamp.equals(that.timestamp)
                && queryType.equals(that.queryType)
                && smtpFrom.equals(that.smtpFrom);
    }

    @Override
    public int hashCode() {
        return Objects.hash(
                protocol,
                uniqueId,
                fullId,
                rawRequest,
                rawResponse,
                remoteAddress,
                timestamp,
                queryType,
                smtpFrom);
    }
}
