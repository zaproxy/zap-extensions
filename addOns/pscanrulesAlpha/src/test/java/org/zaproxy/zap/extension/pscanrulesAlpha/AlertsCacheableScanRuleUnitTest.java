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
package org.zaproxy.zap.extension.pscanrulesAlpha;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

import org.junit.jupiter.api.Test;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;

/* All test-cases should raise either non-storeable alerts
 * or storeable and non-cacheable alerts.
 */
public class AlertsCacheableScanRuleUnitTest extends PassiveScannerTest<CacheableScanRule> {

    private void assertNonStoreable(String expectedEvidence) {
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(
                alertsRaised.get(0).getName(),
                equalTo(Constant.messages.getString("pscanalpha.nonstorable.name")));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo(expectedEvidence));
    }

    private void assertStoreableNonCacheable(String expectedEvidence) {
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(
                alertsRaised.get(0).getName(),
                equalTo(Constant.messages.getString("pscanalpha.storablenoncacheable.name")));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo(expectedEvidence));
    }

    @Override
    protected CacheableScanRule createScanner() {
        return new CacheableScanRule();
    }

    @Test
    public void shouldRaiseAlertNonStoreableWhenHttpMethodInvalid()
            throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("PUT / HTTP/1.1");

        // When
        scanHttpResponseReceive(msg);
        // Then
        assertNonStoreable("PUT ");
    }

    @Test
    public void shouldRaiseAlertNonStoreableWithHttpStatusCode600()
            throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET / HTTP/1.1");
        msg.setResponseHeader("HTTP/1.1 600 OK");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertNonStoreable("600");
    }

    @Test
    public void shouldRaiseAlertNonStoreableWithCacheControlNoStoreDirectiveInRequestHeader()
            throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET / HTTP/1.1\r\n" + "Cache-Control: no-store");
        msg.setResponseHeader("HTTP/1.1 200 OK");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertNonStoreable("no-store");
    }

    @Test
    public void shouldRaiseAlertNonStoreableWithPragmaNoStoreDirectiveInRequestHeader()
            throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET / HTTP/1.1\r\n" + "Pragma: no-store");
        msg.setResponseHeader("HTTP/1.1 200 OK");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertNonStoreable("no-store");
    }

    @Test
    public void shouldRaiseAlertNonStoreableWithCacheControlNoStoreDirectiveInResponseHeader()
            throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET / HTTP/1.1");
        msg.setResponseHeader("HTTP/1.1 200 OK\r\n" + "Cache-Control: no-store");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertNonStoreable("no-store");
    }

    @Test
    public void shouldRaiseAlertNonStoreableWithPragmaNoStoreDirectiveInResponseHeader()
            throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET / HTTP/1.1");
        msg.setResponseHeader("HTTP/1.1 200 OK\r\n" + "Pragma: no-store");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertNonStoreable("no-store");
    }

    @Test
    public void shouldRaiseAlertNonStoreableWhenCacheControlIsPrivate()
            throws HttpMalformedHeaderException {

        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET / HTTP/1.1");
        msg.setResponseHeader("HTTP/1.1 200 OK\r\n" + "Cache-Control: must-revalidate, private");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertNonStoreable("private");
    }

    @Test
    public void
            shouldRaiseAlertNonStoreableWhenAuthorizationHeaderWithWrongCacheControlDirectiveUsed()
                    throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET / HTTP/1.1\r\n" + "Authorization: basic\r\n");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Cache-Control: no-cache\r\n"
                        + "Content-Type: text/xml;charset=UTF-8");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertNonStoreable(HttpHeader.AUTHORIZATION + ":");
    }

    @Test
    public void shouldRaiseAlertNonStoreableWhenAuthorizationHeaderWithoutCacheControlUsed()
            throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET / HTTP/1.1\r\n" + "Authorization: basic\r\n");
        msg.setResponseHeader("HTTP/1.1 200 OK\r\n" + "Content-Type: text/xml;charset=UTF-8");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertNonStoreable(HttpHeader.AUTHORIZATION + ":");
    }

    @Test
    public void
            shouldRaiseAlertNonStoreableWhenExpiresMaxAgeAndPublicDirectiveMissingAndStatusNonCacheableByDefault()
                    throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET / HTTP/1.1");
        msg.setResponseHeader("HTTP/1.1 208 OK\r\n" + "Cache-Control: no-cache");
        // When
        scanHttpResponseReceive(msg);

        // Then
        assertNonStoreable("208");
    }

    @Test
    public void shouldRaiseAlertStoreableNonCacheableWhenNoCacheDirectiveGiven()
            throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET / HTTP/1.1");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Cache-Control: public, no-cache\r\n"
                        + "Content-Type: text/xml;charset=UTF-8");
        // When
        scanHttpResponseReceive(msg);

        // Then
        assertStoreableNonCacheable("no-cache");
    }

    @Test
    public void shouldRaiseAlertStoreableNonCacheableWhenStaleRetrieveProhibited()
            throws HttpMalformedHeaderException {
        shouldRaiseAlertStoreableNonCacheableWhenStaleRetrieveProhibited("must-revalidate");
        shouldRaiseAlertStoreableNonCacheableWhenStaleRetrieveProhibited("proxy-revalidate");
        shouldRaiseAlertStoreableNonCacheableWhenStaleRetrieveProhibited("s-maxage=0");
        shouldRaiseAlertStoreableNonCacheableWhenStaleRetrieveProhibited("max-age=0");
    }

    private void shouldRaiseAlertStoreableNonCacheableWhenStaleRetrieveProhibited(
            String cacheControlDirective) throws HttpMalformedHeaderException {
        // setup is need for private method
        alertsRaised.clear();
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET / HTTP/1.1");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Cache-Control: "
                        + cacheControlDirective
                        + "\r\n"
                        + "Expires: Wed, 02 Oct 2019 06:00:00 GMT\r\n"
                        + "Date: Wed, 02 Oct 2019 07:00:00 GMT");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertStoreableNonCacheable(cacheControlDirective);
    }
}
