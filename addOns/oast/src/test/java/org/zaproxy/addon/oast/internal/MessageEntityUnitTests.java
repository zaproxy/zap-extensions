/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit tests for {@link MessageEntity}. */
class MessageEntityUnitTests extends TestUtils {

    @Test
    void shouldRebuildMessageWithoutResponse() throws Exception {
        // Given
        HttpMessage original = createMessage();
        MessageEntity entity = new MessageEntity(original);
        // When
        HttpMessage rebuilt = entity.toHttpMessage();
        // Then
        assertMessage(rebuilt, original);
    }

    @Test
    void shouldRebuildMessageWithResponse() throws Exception {
        // Given
        HttpMessage original = createMessage();
        original.setResponseHeader("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n");
        original.setResponseBody("Response Body");
        original.setResponseFromTargetHost(true);
        MessageEntity entity = new MessageEntity(original);
        // When
        HttpMessage rebuilt = entity.toHttpMessage();
        // Then
        assertMessage(rebuilt, original);
    }

    private static HttpMessage createMessage() throws Exception {
        HttpMessage message = new HttpMessage(new URI("http://example.com/path?a=b", true));
        message.getRequestHeader().setHeader("X-Header", "Value");
        message.setRequestBody("Request Body");
        message.setTimeSentMillis(1234567890L);
        message.setTimeElapsedMillis(42);
        return message;
    }

    private static void assertMessage(HttpMessage actual, HttpMessage expected) {
        assertThat(
                actual.getRequestHeader().toString(), is(expected.getRequestHeader().toString()));
        assertThat(actual.getRequestBody().toString(), is(expected.getRequestBody().toString()));
        assertThat(actual.getTimeSentMillis(), is(expected.getTimeSentMillis()));
        assertThat(actual.getTimeElapsedMillis(), is(expected.getTimeElapsedMillis()));
        assertThat(actual.isResponseFromTargetHost(), is(expected.isResponseFromTargetHost()));
        assertThat(
                actual.getResponseHeader().toString(), is(expected.getResponseHeader().toString()));
        assertThat(actual.getResponseBody().toString(), is(expected.getResponseBody().toString()));
    }
}
