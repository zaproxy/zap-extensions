/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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
package org.zaproxy.addon.oast.internal;

import java.sql.Timestamp;
import javax.jdo.annotations.Cacheable;
import javax.jdo.annotations.Column;
import javax.jdo.annotations.IdGeneratorStrategy;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;
import org.datanucleus.api.jdo.annotations.CreateTimestamp;
import org.parosproxy.paros.network.HttpMessage;

@Cacheable("false")
@PersistenceCapable(table = "MESSAGE", detachable = "true")
public class MessageEntity {

    @CreateTimestamp private Timestamp createTimestamp;

    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.IDENTITY)
    private Integer id;

    private long timeSentMillis;
    private int timeElapsedMillis;

    @Column(length = 4194304)
    private String reqHeader;

    private byte[] reqBody;

    @Column(length = 4194304)
    private String resHeader;

    private byte[] resBody;
    private boolean responseFromTargetHost;

    public MessageEntity(HttpMessage message) {
        timeSentMillis = message.getTimeSentMillis();
        timeElapsedMillis = message.getTimeElapsedMillis();
        reqHeader = message.getRequestHeader().toString();
        reqBody = message.getRequestBody().getBytes();
        responseFromTargetHost = message.isResponseFromTargetHost();
        if (responseFromTargetHost) {
            resHeader = message.getResponseHeader().toString();
            resBody = message.getResponseBody().getBytes();
        }
    }

    public Timestamp getCreateTimestamp() {
        return createTimestamp;
    }

    public void setCreateTimestamp(Timestamp createTimestamp) {
        this.createTimestamp = createTimestamp;
    }

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public long getTimeSentMillis() {
        return timeSentMillis;
    }

    public void setTimeSentMillis(long timeSentMillis) {
        this.timeSentMillis = timeSentMillis;
    }

    public int getTimeElapsedMillis() {
        return timeElapsedMillis;
    }

    public void setTimeElapsedMillis(int timeElapsedMillis) {
        this.timeElapsedMillis = timeElapsedMillis;
    }

    public String getReqHeader() {
        return reqHeader;
    }

    public void setReqHeader(String reqHeader) {
        this.reqHeader = reqHeader;
    }

    public byte[] getReqBody() {
        return reqBody;
    }

    public void setReqBody(byte[] reqBody) {
        this.reqBody = reqBody;
    }

    public String getResHeader() {
        return resHeader;
    }

    public void setResHeader(String resHeader) {
        this.resHeader = resHeader;
    }

    public byte[] getResBody() {
        return resBody;
    }

    public void setResBody(byte[] resBody) {
        this.resBody = resBody;
    }

    public boolean isResponseFromTargetHost() {
        return responseFromTargetHost;
    }

    public void setResponseFromTargetHost(boolean responseFromTargetHost) {
        this.responseFromTargetHost = responseFromTargetHost;
    }

    public HttpMessage toHttpMessage() throws Exception {
        var message = new HttpMessage();
        message.setRequestHeader(reqHeader);
        message.setRequestBody(reqBody);
        message.setTimeSentMillis(timeSentMillis);
        message.setTimeElapsedMillis(timeElapsedMillis);
        message.setResponseFromTargetHost(responseFromTargetHost);
        if (responseFromTargetHost) {
            message.setRequestHeader(resHeader);
            message.setResponseBody(resBody);
        }
        return message;
    }
}
