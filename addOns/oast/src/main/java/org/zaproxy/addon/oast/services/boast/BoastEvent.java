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
package org.zaproxy.addon.oast.services.boast;

import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Objects;
import net.sf.json.JSONObject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.oast.OastRequest;
import org.zaproxy.zap.network.HttpRequestBody;

public class BoastEvent {

    public static final Logger LOGGER = LogManager.getLogger(BoastEvent.class);

    private final String id;
    private final Instant time;
    private final String serverId;
    private final String receiver;
    private final String remoteAddress;
    private final String dump;
    private final String queryType;

    public BoastEvent(
            String id,
            String time,
            String serverId,
            String receiver,
            String remoteAddress,
            String dump,
            String queryType) {
        this.id = id;
        this.time = Instant.from(DateTimeFormatter.ISO_OFFSET_DATE_TIME.parse(time));
        this.serverId = serverId;
        this.receiver = receiver;
        this.remoteAddress = remoteAddress;
        this.dump = dump;
        this.queryType = queryType;
    }

    public BoastEvent(JSONObject event) {
        this(
                event.getString("id"),
                event.getString("time"),
                event.getString("testID"),
                event.getString("receiver"),
                event.getString("remoteAddress"),
                event.getString("dump"),
                event.optString("queryType"));
    }

    public OastRequest toOastRequest() throws HttpMalformedHeaderException, DatabaseException {
        HttpMessage msg =
                new HttpMessage(
                        new HttpRequestHeader("GET / HTTP/1.1\r\n\r\n"), new HttpRequestBody(dump));
        msg.setTimeSentMillis(time.toEpochMilli());
        if (("HTTP".equals(receiver) || "HTTPS".equals(receiver)) && dump.contains("\r\n\r\n")) {
            try {
                int separatorIndex = dump.indexOf("\r\n\r\n") + 4;
                String headerString = dump.substring(0, separatorIndex);
                String bodyString = dump.substring(separatorIndex);
                msg.setRequestHeader(headerString);
                msg.setRequestBody(bodyString);
            } catch (Exception e) {
                LOGGER.info(Constant.messages.getString("oast.boast.event.badMsgDump"));
            }
        } else if ("DNS".equals(receiver)) {
            String searchString = "QUESTION SECTION:\n;";
            int requestUriIndex = dump.indexOf(searchString) + searchString.length();
            String requestUri =
                    dump.substring(requestUriIndex, dump.indexOf("\t", requestUriIndex));
            if (!requestUri.contains("://")) {
                requestUri = "http://" + requestUri;
            }
            String method = "DNS" + (queryType.isEmpty() ? "" : "_" + queryType);
            String requestHeader = method + " " + requestUri + " HTTP/1.1\r\n\r\n";
            msg.setRequestHeader(requestHeader);
        }
        return OastRequest.create(
                msg, remoteAddress, Constant.messages.getString("oast.boast.name"));
    }

    public String getDump() {
        return dump;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        BoastEvent that = (BoastEvent) o;
        return id.equals(that.id)
                && time.equals(that.time)
                && serverId.equals(that.serverId)
                && receiver.equals(that.receiver)
                && remoteAddress.equals(that.remoteAddress)
                && dump.equals(that.dump)
                && queryType.equals(that.queryType);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, time, serverId, receiver, remoteAddress, dump, queryType);
    }
}
