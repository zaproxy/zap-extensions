/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package org.zaproxy.addon.grpc.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.NameValuePair;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;

class VariantGrpcInjectionUnitTest {

    private VariantGrpc variantGrpc;

    @BeforeEach
    void setUp() {
        variantGrpc = new VariantGrpc();
    }

    @Test
    void shouldExposeOnlyStringLeavesAsInjectableParameters()
            throws HttpMalformedHeaderException {
        HttpMessage httpMessage =
                createHttpMessage(
                        "AAAAADEKC2pvaG4gTWlsbGVyEB4aIDEyMzQgTWFpbiBTdC4gQW55dG93biwgVVNBIDEyMzQ1");

        variantGrpc.setMessage(httpMessage);

        List<NameValuePair> params = variantGrpc.getParamList();
        assertEquals(2, params.size());
        assertEquals("1:2", params.get(0).getName());
        assertEquals("\"john Miller\"", params.get(0).getValue());
        assertEquals("3:2", params.get(1).getName());
        assertEquals("\"1234 Main St. Anytown, USA 12345\"", params.get(1).getValue());
    }

    @Test
    void shouldMutateRepeatedStringByPosition() throws HttpMalformedHeaderException {
        HttpMessage httpMessage = createHttpMessage("AAAAAA4IARIBYRIBYhIBYxIBZA");

        variantGrpc.setMessage(httpMessage);
        NameValuePair thirdValue = variantGrpc.getParamList().get(2);
        variantGrpc.setParameter(httpMessage, thirdValue, thirdValue.getName(), "payload");

        variantGrpc.setMessage(httpMessage);
        assertEquals("\"a\"", variantGrpc.getParamList().get(0).getValue());
        assertEquals("\"b\"", variantGrpc.getParamList().get(1).getValue());
        assertEquals("\"payload\"", variantGrpc.getParamList().get(2).getValue());
        assertEquals("\"d\"", variantGrpc.getParamList().get(3).getValue());
    }

    @Test
    void shouldRoundTripSpecialCharactersAndEmptyString()
            throws HttpMalformedHeaderException {
        HttpMessage httpMessage = createHttpMessage("AAAAAAMKAXg");

        variantGrpc.setMessage(httpMessage);
        NameValuePair parameter = variantGrpc.getParamList().get(0);
        variantGrpc.setParameter(
                httpMessage,
                parameter,
                parameter.getName(),
                "line1\n\"quoted\"\\line2");

        variantGrpc.setMessage(httpMessage);
        assertEquals(
                "\"line1\\n\\\"quoted\\\"\\\\line2\"",
                variantGrpc.getParamList().get(0).getValue());

        parameter = variantGrpc.getParamList().get(0);
        variantGrpc.setParameter(httpMessage, parameter, parameter.getName(), "");

        variantGrpc.setMessage(httpMessage);
        assertEquals("\"\"", variantGrpc.getParamList().get(0).getValue());
    }

    @Test
    void shouldRemoveParameterWhenNullNameAndValueAreRequested()
            throws HttpMalformedHeaderException {
        HttpMessage httpMessage =
                createHttpMessage(
                        "AAAAADEKC2pvaG4gTWlsbGVyEB4aIDEyMzQgTWFpbiBTdC4gQW55dG93biwgVVNBIDEyMzQ1");

        variantGrpc.setMessage(httpMessage);
        NameValuePair parameter = variantGrpc.getParamList().get(0);

        variantGrpc.setParameter(httpMessage, parameter, null, null);

        variantGrpc.setMessage(httpMessage);
        List<NameValuePair> params = variantGrpc.getParamList();
        assertEquals(1, params.size());
        assertEquals("3:2", params.get(0).getName());
        assertEquals("\"1234 Main St. Anytown, USA 12345\"", params.get(0).getValue());
    }

    private static HttpMessage createHttpMessage(String encodedRequestBody)
            throws HttpMalformedHeaderException {
        HttpRequestHeader requestHeader = new HttpRequestHeader();
        requestHeader.setMessage("POST /abc/xyz HTTP/1.1");
        requestHeader.setHeader(HttpHeader.CONTENT_TYPE, "application/grpc-web-text");
        HttpMessage httpMessage = new HttpMessage(requestHeader);
        httpMessage.setRequestBody(encodedRequestBody);
        return httpMessage;
    }
}
