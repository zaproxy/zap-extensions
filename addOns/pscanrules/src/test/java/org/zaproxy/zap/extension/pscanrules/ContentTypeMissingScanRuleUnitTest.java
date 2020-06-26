/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2019 The ZAP Development Team
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
package org.zaproxy.zap.extension.pscanrules;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

import org.junit.jupiter.api.Test;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpResponseHeader;

public class ContentTypeMissingScanRuleUnitTest
        extends PassiveScannerTest<ContentTypeMissingScanRule> {

    @Override
    protected ContentTypeMissingScanRule createScanner() {
        return new ContentTypeMissingScanRule();
    }

    private HttpMessage createMessage() throws HttpMalformedHeaderException {
        HttpMessage msg = new HttpMessage();

        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");

        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Cache-Control: no-cache, no-store, must-revalidate\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");

        return msg;
    }

    @Test
    public void shoudNotAlertIfResponseBodyIsEmpty() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = createMessage();
        msg.getResponseHeader().setHeader(HttpResponseHeader.CONTENT_TYPE, "");
        msg.setResponseBody("");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void shoudNotAlertIfContentTypePresentInResponse() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = createMessage();
        msg.getResponseHeader()
                .setHeader(HttpResponseHeader.CONTENT_TYPE, "text/html;charset=ISO-8859-1");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void shoudAlertIfContentTypePresentButEmptyInResponse()
            throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = createMessage();
        msg.getResponseHeader().setHeader(HttpResponseHeader.CONTENT_TYPE, "");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(
                alertsRaised.get(0).getName(),
                equalTo(Constant.messages.getString("pscanrules.contenttypemissing.name.empty")));
    }

    @Test
    public void shoudAlertIfContentTypeNotPresentInResponse() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = createMessage();
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(
                alertsRaised.get(0).getName(),
                equalTo(Constant.messages.getString("pscanrules.contenttypemissing.name")));
    }
}
