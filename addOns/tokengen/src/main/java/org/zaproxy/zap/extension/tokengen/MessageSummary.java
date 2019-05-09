/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2012 The ZAP Development Team
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
package org.zaproxy.zap.extension.tokengen;

import java.util.Date;
import org.parosproxy.paros.network.HttpMessage;

public class MessageSummary {

    private final Date requestTimestamp;
    private final String method;
    private final String uriString;
    private final Integer statusCodeStr;
    private final String reasonPhrase;
    private final Long timeElapsedMillis;
    private final Long responseBodyLength;
    private final String token;
    private boolean goodResponse = true;

    public MessageSummary(HttpMessage msg) {
        this.requestTimestamp = new Date(msg.getTimeSentMillis());
        this.method = msg.getRequestHeader().getMethod();
        this.uriString = msg.getRequestHeader().getURI().toString();
        this.statusCodeStr = Integer.valueOf(msg.getResponseHeader().getStatusCode());
        this.reasonPhrase = msg.getResponseHeader().getReasonPhrase();
        this.timeElapsedMillis = Long.valueOf(msg.getTimeElapsedMillis());
        this.responseBodyLength = Long.valueOf(msg.getResponseBody().toString().length());
        this.token = msg.getNote(); // The note is used to store the token
        if (msg.getResponseHeader().isEmpty()) {
            this.goodResponse = false;
        }
    }

    public String getMethod() {
        return method;
    }

    public String getUri() {
        return uriString;
    }

    public Integer getStatusCode() {
        return statusCodeStr;
    }

    public String getReasonPhrase() {
        return reasonPhrase;
    }

    public Long getTimeElapsedMillis() {
        return timeElapsedMillis;
    }

    public Long getResponseBodyLength() {
        return responseBodyLength;
    }

    public String getToken() {
        return token;
    }

    public Date getRequestTimestamp() {
        return requestTimestamp;
    }

    public boolean isGoodResponse() {
        return goodResponse;
    }
}
