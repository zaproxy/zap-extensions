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
package org.zaproxy.zap.extension.frontendscanner;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit test for {@link FrontEndScannerProxyListener}. */
public class FrontEndScannerProxyListenerUnitTest extends TestUtils {

    private static final String HOSTNAME = "example.com";

    private FrontEndScannerProxyListener frontEndScannerProxyListener;
    private FrontEndScannerOptions options;
    private HttpMessage msg;

    @BeforeEach
    public void setUp() throws URIException, HttpMalformedHeaderException {
        FrontEndScannerAPI api = mock(FrontEndScannerAPI.class);
        options = mock(FrontEndScannerOptions.class);

        HistoryReference ref = mock(HistoryReference.class, withSettings().lenient());
        when(ref.getHistoryId()).thenReturn(42);

        frontEndScannerProxyListener = new FrontEndScannerProxyListener(api, options);

        msg = new HttpMessage(new URI("https", HOSTNAME, "/", ""));
        msg.getResponseHeader().setHeader(HttpResponseHeader.CONTENT_TYPE, "text/html");
        msg.setHistoryRef(ref);
    }

    @ParameterizedTest
    @ValueSource(strings = {"Content-Security-Policy", "X-Content-Security-Policy", "X-WebKit-CSP"})
    public void testRemovesCSPFromHttpResponsesIfInjecting(String header) {
        // Given
        when(options.isEnabled()).thenReturn(true);
        String htmlBody =
                "<!doctype html><html lang='en'><head><script></script></head><body></body></html>";
        msg.setResponseBody(htmlBody);

        msg.getResponseHeader().setHeader(header, "value");

        // When
        frontEndScannerProxyListener.onHttpResponseReceive(msg);

        // Then
        String result = msg.getResponseHeader().getHeader(header);
        assertNull(result);
    }

    @Test
    public void testInjectTheFrontEndTrackerBeforeOtherScriptsInHeadTag() {
        // Given
        when(options.isEnabled()).thenReturn(true);
        String htmlBody =
                "<!doctype html><html lang='en'><head><script></script></head><body></body></html>";
        msg.setResponseBody(htmlBody);

        // When
        frontEndScannerProxyListener.onHttpResponseReceive(msg);

        // Then
        String expectedHtmlFormat =
                "<!doctype html><html lang='en'><head><script src='https:\\/\\/"
                        + HOSTNAME
                        + "\\/zapCallBackUrl\\/-?[0-9]+\\?action=getFile&filename=front-end-scanner.js&historyReferenceId=42'><\\/script><script><\\/script><\\/head><body><\\/body></html>";
        String result = msg.getResponseBody().toString();

        assertTrue(result.matches(expectedHtmlFormat));
    }

    @Test
    public void testInjectAfterMetaTagInHeadTag() {
        // Given
        when(options.isEnabled()).thenReturn(true);
        String htmlBody = "<!doctype html><html lang='en'><head><meta></head><body></body></html>";
        msg.setResponseBody(htmlBody);

        // When
        frontEndScannerProxyListener.onHttpResponseReceive(msg);

        // Then
        String expectedHtmlFormat =
                "<!doctype html><html lang='en'><head><meta><script src='https:\\/\\/"
                        + HOSTNAME
                        + "\\/zapCallBackUrl\\/-?[0-9]+\\?action=getFile&filename=front-end-scanner.js&historyReferenceId=42'><\\/script><\\/head><body><\\/body></html>";
        String result = msg.getResponseBody().toString();

        assertTrue(result.matches(expectedHtmlFormat));
    }

    @Test
    public void testInjectAfterAllMetaTagsInHeadTag() {
        // Given
        when(options.isEnabled()).thenReturn(true);
        String htmlBody =
                "<!doctype html><html lang='en'><head><meta><meta></head><body></body></html>";
        msg.setResponseBody(htmlBody);

        // When
        frontEndScannerProxyListener.onHttpResponseReceive(msg);

        // Then
        String expectedHtmlFormat =
                "<!doctype html><html lang='en'><head><meta><meta><script src='https:\\/\\/"
                        + HOSTNAME
                        + "\\/zapCallBackUrl\\/-?[0-9]+\\?action=getFile&filename=front-end-scanner.js&historyReferenceId=42'><\\/script><\\/head><body><\\/body></html>";
        String result = msg.getResponseBody().toString();

        assertTrue(result.matches(expectedHtmlFormat));
    }

    @Test
    public void testInjectionShouldBeSuccessfulWithoutHead() {
        // Given
        when(options.isEnabled()).thenReturn(true);
        String htmlBody = "<!doctype html><html lang='en'><body></body></head></html>";
        msg.setResponseBody(htmlBody);

        // When
        frontEndScannerProxyListener.onHttpResponseReceive(msg);

        // Then
        String expectedHtmlFormat =
                "<!doctype html><html lang='en'><head><script src='https:\\/\\/"
                        + HOSTNAME
                        + "\\/zapCallBackUrl\\/-?[0-9]+\\?action=getFile&filename=front-end-scanner.js&historyReferenceId=42'><\\/script><\\/head><body><\\/body></head></html>";
        String result = msg.getResponseBody().toString();

        assertTrue(result.matches(expectedHtmlFormat));
    }

    @Test
    public void testInjectionShouldBeSuccessfulWithEmptyHead() {
        // Given
        when(options.isEnabled()).thenReturn(true);
        String htmlBody = "<!doctype html><html lang='en'><head></head><body></body></html>";
        msg.setResponseBody(htmlBody);

        // When
        frontEndScannerProxyListener.onHttpResponseReceive(msg);

        // Then
        String expectedHtmlFormat =
                "<!doctype html><html lang='en'><head><script src='https:\\/\\/"
                        + HOSTNAME
                        + "\\/zapCallBackUrl\\/-?[0-9]+\\?action=getFile&filename=front-end-scanner.js&historyReferenceId=42'><\\/script><\\/head><body><\\/body></html>";
        String result = msg.getResponseBody().toString();

        assertTrue(result.matches(expectedHtmlFormat));
    }

    @Test
    public void testInjectionShouldBeSuccessfulWithoutHtmlTag() {
        // Given
        when(options.isEnabled()).thenReturn(true);
        String htmlBody = "<head></head><body></body>";
        msg.setResponseBody(htmlBody);

        // When
        frontEndScannerProxyListener.onHttpResponseReceive(msg);

        // Then
        String expectedHtmlFormat =
                "<head><script src='https:\\/\\/"
                        + HOSTNAME
                        + "\\/zapCallBackUrl\\/-?[0-9]+\\?action=getFile&filename=front-end-scanner.js&historyReferenceId=42'><\\/script><\\/head><body><\\/body>";
        String result = msg.getResponseBody().toString();

        assertTrue(result.matches(expectedHtmlFormat));
    }

    @Test
    public void testInjectionShouldBeSuccessfulWithoutHtmlNorHeadTag() {
        // Given
        when(options.isEnabled()).thenReturn(true);
        String htmlBody = "<body></body>";
        msg.setResponseBody(htmlBody);

        // When
        frontEndScannerProxyListener.onHttpResponseReceive(msg);

        // Then
        String expectedHtmlFormat =
                "<head><script src='https:\\/\\/"
                        + HOSTNAME
                        + "\\/zapCallBackUrl\\/-?[0-9]+\\?action=getFile&filename=front-end-scanner.js&historyReferenceId=42'><\\/script><\\/head><body><\\/body>";
        String result = msg.getResponseBody().toString();

        assertTrue(result.matches(expectedHtmlFormat));
    }

    @ParameterizedTest
    @ValueSource(strings = {"Content-Security-Policy", "X-Content-Security-Policy", "X-WebKit-CSP"})
    public void testCSPisNotRemovedIfNotEnabledInOptions(String header) {
        // Given
        when(options.isEnabled()).thenReturn(false);
        String htmlBody = "<!doctype html><html lang='en'><head></head><body></body></html>";
        msg.setResponseBody(htmlBody);

        msg.getResponseHeader().setHeader(header, "value");

        // When
        frontEndScannerProxyListener.onHttpResponseReceive(msg);

        // Then
        String result = msg.getResponseHeader().getHeader(header);
        assertNotNull(result);
    }

    @Test
    public void testNothingIsInjectedIfNotEnabledInOptions() {
        // Given
        when(options.isEnabled()).thenReturn(false);
        String htmlBody = "<!doctype html><html lang='en'><head></head><body></body></html>";
        msg.setResponseBody(htmlBody);

        // When
        frontEndScannerProxyListener.onHttpResponseReceive(msg);

        // Then
        String expectedHtmlFormat =
                "<!doctype html><html lang='en'><head><\\/head><body><\\/body></html>";
        String result = msg.getResponseBody().toString();

        assertTrue(result.matches(expectedHtmlFormat));
    }
}
