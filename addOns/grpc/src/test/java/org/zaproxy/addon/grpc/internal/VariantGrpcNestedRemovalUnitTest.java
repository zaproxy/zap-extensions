/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package org.zaproxy.addon.grpc.internal;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.util.Base64;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.NameValuePair;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;

class VariantGrpcNestedRemovalUnitTest {

    private VariantGrpc variantGrpc;

    @BeforeEach
    void setUp() {
        variantGrpc = new VariantGrpc();
    }

    @Test
    void shouldRemoveLastFieldFromDeepNestedMessage() throws HttpMalformedHeaderException {
        HttpMessage message =
                createGrpcWebTextMessage(
                        "AAAAAEEKEEhlbGxvLCBQcm90b2J1ZiESJwoESm9obhIGTWlsbGVyGhcKBEpvaG4QAhoNCgtIZWxsbyBXb3JsZBjqrcDlJA");
        variantGrpc.setMessage(message);
        NameValuePair target = findParameter("2:2N.3:2N.3:2N.1:2");

        String updated = variantGrpc.setParameter(message, target, null, null);

        assertNotNull(updated);
        assertEquals(
                "AAAAADQKEEhlbGxvLCBQcm90b2J1ZiESGgoESm9obhIGTWlsbGVyGgoKBEpvaG4QAhoAGOqtwOUk",
                message.getRequestBody().toString());
    }

    @Test
    void shouldRemoveOnlyFieldFromNativeGrpcMessage() throws HttpMalformedHeaderException {
        HttpMessage message =
                createNativeGrpcMessage(Base64.getDecoder().decode("AAAAAAMKAXg="));
        variantGrpc.setMessage(message);
        NameValuePair target = variantGrpc.getParamList().get(0);

        String updated = variantGrpc.setParameter(message, target, null, null);

        assertNotNull(updated);
        assertEquals("", updated);
        assertArrayEquals(new byte[] {0, 0, 0, 0, 0}, message.getRequestBody().getBytes());
    }

    private NameValuePair findParameter(String name) {
        return variantGrpc.getParamList().stream()
                .filter(parameter -> name.equals(parameter.getName()))
                .findFirst()
                .orElseThrow();
    }

    private static HttpMessage createGrpcWebTextMessage(String encodedRequestBody)
            throws HttpMalformedHeaderException {
        HttpRequestHeader requestHeader = new HttpRequestHeader();
        requestHeader.setMessage("POST /abc/xyz HTTP/1.1");
        requestHeader.setHeader(HttpHeader.CONTENT_TYPE, "application/grpc-web-text");
        HttpMessage message = new HttpMessage(requestHeader);
        message.setRequestBody(encodedRequestBody);
        return message;
    }

    private static HttpMessage createNativeGrpcMessage(byte[] encodedRequestBody)
            throws HttpMalformedHeaderException {
        HttpRequestHeader requestHeader = new HttpRequestHeader();
        requestHeader.setMessage("POST /abc/xyz HTTP/1.1");
        requestHeader.setHeader(HttpHeader.CONTENT_TYPE, "application/grpc");
        HttpMessage message = new HttpMessage(requestHeader);
        message.setRequestBody(encodedRequestBody);
        return message;
    }
}
