/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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

import java.util.Date;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.commons.httpclient.util.DateUtil;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;

/* All test-cases should raise storeable and cacheable alerts
 * or should verfiy the absence of exceptions.
 */
public class CacheableScanRuleUnitTest extends PassiveScannerTest<CacheableScanRule> {

    private HttpMessage createMessage() throws URIException {
        HttpRequestHeader requestHeader = new HttpRequestHeader();
        requestHeader.setMethod("GET");
        requestHeader.setURI(new URI("https://example.com/fred/", false));

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(requestHeader);
        return msg;
    }

    private HttpMessage createMessageBasicAuthorization() throws URIException {
        HttpRequestHeader requestHeader = new HttpRequestHeader();
        requestHeader.setMethod("GET");
        requestHeader.setURI(new URI("https://example.com/fred/", false));
        requestHeader.addHeader(HttpHeader.AUTHORIZATION, "basic");

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(requestHeader);
        return msg;
    }

    private void assertStoreAndCacheable(String expectedEvidence) {
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo(expectedEvidence));
        assertThat(
                alertsRaised.get(0).getName(),
                equalTo(Constant.messages.getString("pscanalpha.storablecacheable.name")));
    }

    @Override
    protected CacheableScanRule createScanner() {
        return new CacheableScanRule();
    }

    @Test
    public void scannerNameShouldMatch() {
        // Quick test to verify scan rule name which is used in the policy dialog but not
        // alerts

        // Given
        CacheableScanRule thisScanner = createScanner();
        // Then
        assertThat(thisScanner.getName(), equalTo("Content Cacheability"));
    }

    @Test
    public void shouldNotCauseExceptionWhenExpiresHeaderHasZeroValue()
            throws URIException, HttpMalformedHeaderException {
        // Given
        HttpMessage msg = createMessage();
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Cache-Control: must-revalidate,private\r\n"
                        + "Pragma: must-revalidate,no-cache\r\n"
                        + "Content-Type: text/xml;charset=UTF-8\r\n"
                        + "Expires: 0\r\n"
                        + // http-date expected, Ex: "Wed, 21 Oct 2015 07:28:00 GMT"
                        "Date: "
                        + DateUtil.formatDate(new Date())
                        + "\r\n\r\n");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
    }

    @Test
    public void shouldRaiseAlertStoreAndCacheableWhenStatusNonCacheableByDefaultAndExpiryDateGiven()
            throws URIException, HttpMalformedHeaderException {
        // Given
        HttpMessage msg = createMessage();
        msg.setResponseHeader(
                "HTTP/1.1 207 OK\r\n"
                        + "Cache-Control: must-revalidate\r\n"
                        + "Expires: Wed, 02 Oct 2019 07:00:00 GMT\r\n"
                        + "Date: Wed, 02 Oct 2019 06:00:00 GMT");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertStoreAndCacheable("Wed, 02 Oct 2019 07:00:00 GMT");
    }

    @Test
    public void shouldRaiseAlertStoreAndCacheableWhenStatusNonCacheableByDefaultAndCacheIsPublic()
            throws URIException, HttpMalformedHeaderException {
        // Given
        HttpMessage msg = createMessage();
        msg.setResponseHeader("HTTP/1.1 207 OK\r\n" + "Cache-Control: public");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertStoreAndCacheable("");
    }

    @Test
    public void shouldRaiseAlertStoreAndCacheableWhenStatusNonCacheableByDefaultAndMaxAgeGiven()
            throws URIException, HttpMalformedHeaderException {
        // Given
        HttpMessage msg = createMessage();
        msg.setResponseHeader("HTTP/1.1 207 OK\r\n" + "Cache-Control: max-age=100");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertStoreAndCacheable("max-age=100");
    }

    @Test
    public void shouldRaiseAlertStoreAndCacheableWhenStatusNonCacheableByDefaultAndS_MaxAgeGiven()
            throws URIException, HttpMalformedHeaderException {
        // Given
        HttpMessage msg = createMessage();
        msg.setResponseHeader("HTTP/1.1 207 OK\r\n" + "Cache-Control: s-maxage=100");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertStoreAndCacheable("s-maxage=100");
    }

    @Test
    public void shouldRaiseAlertStoreAndCacheableWhenStatusCacheableByDefault()
            throws URIException, HttpMalformedHeaderException {
        shouldRaiseAlertStoreAndCacheableWhenStatusCacheableByDefault("200");
        shouldRaiseAlertStoreAndCacheableWhenStatusCacheableByDefault("203");
        shouldRaiseAlertStoreAndCacheableWhenStatusCacheableByDefault("204");
        shouldRaiseAlertStoreAndCacheableWhenStatusCacheableByDefault("206");
        shouldRaiseAlertStoreAndCacheableWhenStatusCacheableByDefault("300");
        shouldRaiseAlertStoreAndCacheableWhenStatusCacheableByDefault("301");
        shouldRaiseAlertStoreAndCacheableWhenStatusCacheableByDefault("404");
        shouldRaiseAlertStoreAndCacheableWhenStatusCacheableByDefault("405");
        shouldRaiseAlertStoreAndCacheableWhenStatusCacheableByDefault("410");
        shouldRaiseAlertStoreAndCacheableWhenStatusCacheableByDefault("414");
        shouldRaiseAlertStoreAndCacheableWhenStatusCacheableByDefault("501");
    }

    private void shouldRaiseAlertStoreAndCacheableWhenStatusCacheableByDefault(String statusCode)
            throws URIException, HttpMalformedHeaderException {
        // setup for private method needed
        alertsRaised.clear();
        // Given
        HttpMessage msg = createMessage();
        msg.setResponseHeader(
                "HTTP/1.1 " + statusCode + " OK\r\n" + "Cache-Control: must-revalidate");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertStoreAndCacheable("");
    }

    @Test
    public void shouldRaiseAlertStoreAndCacheableWhenAuthorizationNeededAndCacheMustRevalidated()
            throws URIException, HttpMalformedHeaderException {
        // Given
        HttpMessage msg = createMessageBasicAuthorization();
        msg.setResponseHeader("HTTP/1.1 200 OK\r\n" + "Cache-Control: must-revalidate");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertStoreAndCacheable("");
    }

    @Test
    public void shouldRaiseAlertStoreAndCacheableWhenAuthorizationNeededAndCacheIsPublic()
            throws URIException, HttpMalformedHeaderException {
        // Given
        HttpMessage msg = createMessageBasicAuthorization();
        msg.setResponseHeader("HTTP/1.1 200 OK\r\n" + "Cache-Control: public");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertStoreAndCacheable("");
    }

    @Test
    public void shouldRaiseAlertStoreAndCacheableWhenAuthorizationNeededAndS_MaxAgeCacheGiven()
            throws URIException, HttpMalformedHeaderException {
        // Given
        HttpMessage msg = createMessageBasicAuthorization();
        msg.setResponseHeader("HTTP/1.1 200 OK\r\n" + "Cache-Control: s-maxage=100");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertStoreAndCacheable("s-maxage=100");
    }

    @Test
    public void shouldRaiseAlertStoreAndCacheableWhenCacheIsFreshAndS_MaxAgeDirectiveIsSet()
            throws URIException, HttpMalformedHeaderException {
        // Given
        HttpMessage msg = createMessage();
        msg.setResponseHeader("HTTP/1.1 200 OK\r\n" + "Cache-Control: s-maxage=100, public");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertStoreAndCacheable("s-maxage=100");
    }

    @Test
    public void shouldRaiseAlertStoreAndCacheableWhenCacheIsFreshAndMaxAgeDirectiveIsSet()
            throws URIException, HttpMalformedHeaderException {
        // Given
        HttpMessage msg = createMessage();
        msg.setResponseHeader("HTTP/1.1 200 OK\r\n" + "Cache-Control: max-age=100,public");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertStoreAndCacheable("max-age=100,public");
    }

    @Test
    public void shouldRaiseAlertStoreAndCacheableWhenCacheIsFreshAndExpirySpecified()
            throws URIException, HttpMalformedHeaderException {
        // Given
        HttpMessage msg = createMessage();
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Cache-Control: public\r\n"
                        + "Expires: Wed, 02 Oct 2019 08:00:00 GMT\r\n"
                        + "Date: Wed, 02 Oct 2019 07:00:00 GMT");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertStoreAndCacheable("Wed, 02 Oct 2019 08:00:00 GMT");
    }

    @Test
    public void shouldRaiseAlertStoreAndCacheableCacheIsFreshWhenNoLifetimeSpecified()
            throws URIException, HttpMalformedHeaderException {
        // Given
        HttpMessage msg = createMessage();
        msg.setResponseHeader("HTTP/1.1 200 OK\r\n" + "Cache-Control: public");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertStoreAndCacheable("");
        assertThat(
                alertsRaised.get(0).getOtherInfo(),
                equalTo(
                        Constant.messages.getString(
                                "pscanalpha.storablecacheable.otherinfo.liberallifetimeheuristic")));
    }

    @Test
    public void shouldRaiseAlertStoreAndCacheableWhenStaleRetrieveAllowed()
            throws URIException, HttpMalformedHeaderException {
        // Given
        HttpMessage msg = createMessage();
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Cache-Control: public\r\n"
                        + "Expires: Wed, 02 Oct 2019 06:00:00 GMT\r\n"
                        + "Date: Wed, 02 Oct 2019 07:00:00 GMT");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertStoreAndCacheable("");
    }
}
