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
package org.zaproxy.addon.grpc.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.NameValuePair;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;

public class VariantGrpcUnitTest {
    private VariantGrpc variantGrpc;

    @BeforeEach
    void setUp() {
        variantGrpc = new VariantGrpc();
    }

    @Test
    void shouldSetParameterForNestedMessage() throws HttpMalformedHeaderException {
        String encodedRequestBody =
                "AAAAAEEKEEhlbGxvLCBQcm90b2J1ZiESJwoESm9obhIGTWlsbGVyGhcKBEpvaG4QAhoNCgtIZWxsbyBXb3JsZBjqrcDlJA";
        String expectedOutput =
                "1:2::\"Hello, Protobuf!\"\n2:2N::{\n1:2::\"John\"\n2:2::\"Miller\"\n3:2N::{\n1:2::\"John\"\n2:0::2\n3:2N::{\n1:2::\"../../../../admin/\"\n}\n}\n}\n3:0::9876543210\n";

        HttpRequestHeader httpRequestHeader = new HttpRequestHeader();
        httpRequestHeader.setMessage("POST /abc/xyz HTTP/1.1");
        httpRequestHeader.setHeader(HttpHeader.CONTENT_TYPE, "application/grpc-web-text");
        HttpMessage httpMessage = new HttpMessage(httpRequestHeader);
        httpMessage.setRequestBody(encodedRequestBody);
        variantGrpc.setMessage(httpMessage);
        String param = "2:2N.3:2N.3:2N.1:2";
        String payload = "../../../../admin/";
        NameValuePair originalPair =
                new NameValuePair(VariantGrpc.TYPE_GRPC_WEB_TEXT, param, "Hello World", 0);
        String newMessageWithPayload =
                variantGrpc.setParameter(httpMessage, originalPair, param, payload);

        assertEquals(expectedOutput, newMessageWithPayload);
    }

    @Test
    void shouldSetParameter() throws HttpMalformedHeaderException {

        String encodedRequestBody =
                "AAAAAEEKEEhlbGxvLCBQcm90b2J1ZiESJwoESm9obhIGTWlsbGVyGhcKBEpvaG4QAhoNCgtIZWxsbyBXb3JsZBjqrcDlJA";
        String expectedOutput =
                "1:2::\"../../../../admin/\"\n2:2N::{\n1:2::\"John\"\n2:2::\"Miller\"\n3:2N::{\n1:2::\"John\"\n2:0::2\n3:2N::{\n1:2::\"Hello World\"\n}\n}\n}\n3:0::9876543210\n";

        HttpRequestHeader httpRequestHeader = new HttpRequestHeader();
        httpRequestHeader.setMessage("POST /abc/xyz HTTP/1.1");
        httpRequestHeader.setHeader(HttpHeader.CONTENT_TYPE, "application/grpc-web-text");
        HttpMessage httpMessage = new HttpMessage(httpRequestHeader);
        httpMessage.setRequestBody(encodedRequestBody);

        variantGrpc.setMessage(httpMessage);
        String param = "1:2";
        String payload = "../../../../admin/";
        NameValuePair originalPair =
                new NameValuePair(VariantGrpc.TYPE_GRPC_WEB_TEXT, param, "Hello World", 0);
        String newMessageWithPayload =
                variantGrpc.setParameter(httpMessage, originalPair, param, payload);

        assertEquals(expectedOutput, newMessageWithPayload);
    }
}
