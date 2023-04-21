/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
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
package org.zaproxy.addon.graphql;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;

import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.testutils.TestUtils;

class MessageValidatorUnitTest extends TestUtils {
    @BeforeEach
    void setup() throws Exception {
        setUpZap();
    }

    @Test
    void nonExistentContentTypeHeader() throws Exception {
        HttpMessage message = new HttpMessage(new URI("http://example.com", true));
        assertEquals(MessageValidator.validate(message), MessageValidator.Result.INVALID);
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "{\"data\":{\"name\":\"John Doe\"}}",
                "{\n\t\"data\": {\n\t\t\"name\": \"John Doe\"\r\n\t}\r\n}",
                "{\"errors\": [{\"message\": \"Cannot query field \\\"name\\\" on type \\\"Query\\\".\"}]}",
                "{\"extensions\": {\"tracing\": {\"version\": 1}}, \"data\": {\"name\": \"John Doe\"}}"
            })
    void shouldRecognizeGraphQlEndpointResponse(String response) {
        assertThat(
                MessageValidator.isGraphQlEndpointResponse(response, "application/json"), is(true));
    }
}
