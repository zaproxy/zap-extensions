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
package org.zaproxy.zap.extension.pscanrulesBeta;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.http.HttpDateUtils;

/* All test-cases should raise storeable and cacheable alerts
 * or should verify the absence of exceptions.
 */
class CacheableScanRuleUnitTest extends PassiveScannerTest<CacheableScanRule> {

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
                equalTo(Constant.messages.getString("pscanbeta.storablecacheable.name")));
    }

    @Override
    protected CacheableScanRule createScanner() {
        return new CacheableScanRule();
    }

    @Test
    void scannerNameShouldMatch() {
        // Quick test to verify scan rule name which is used in the policy dialog but not
        // alerts

        // Given
        CacheableScanRule thisScanner = createScanner();
        // Then
        assertThat(thisScanner.getName(), equalTo("Content Cacheability"));
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(tags.size(), is(equalTo(1)));
        assertThat(
                tags.containsKey(CommonAlertTag.WSTG_V42_ATHN_06_CACHE_WEAKNESS.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.WSTG_V42_ATHN_06_CACHE_WEAKNESS.getTag()),
                is(equalTo(CommonAlertTag.WSTG_V42_ATHN_06_CACHE_WEAKNESS.getValue())));
    }

    @Test
    void shouldReturnExampleAlerts() {
        // Given / When
        List<Alert> alerts = rule.getExampleAlerts();
        // Then
        assertThat(alerts.size(), is(equalTo(3)));
    }

    @Test
    void shouldNotCauseExceptionWhenExpiresHeaderHasZeroValue()
            throws URIException, HttpMalformedHeaderException {
        // Given
        HttpMessage msg = createMessage();
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Cache-Control: must-revalidate,private\r\n"
                        + "Pragma: must-revalidate,no-cache\r\n"
                        + "Content-Type: text/xml;charset=UTF-8\r\n"
                        + "Expires: 0\r\n"
                        + "Date: "
                        + HttpDateUtils.format(Instant.now())
                        + "\r\n\r\n");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "s-maxage=600,max-age=0",
                "s-maxage=600, max-age=0",
                "s-maxage=600 ,max-age=0",
                "s-maxage=600 , max-age=0",
                "s-maxage=600",
                "s-maxage=600,",
                "max-age=0,s-maxage=600"
            })
    void shouldHandleVariousSMaxAgeFormats(String headerValue)
            throws URIException, HttpMalformedHeaderException {
        // Given
        HttpMessage msg = createMessage();
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Cache-Control: "
                        + headerValue
                        + "\r\n"
                        + "Pragma: must-revalidate,no-cache\r\n"
                        + "Content-Type: text/xml;charset=UTF-8\r\n"
                        + "Expires: 0\r\n"
                        + "Date: "
                        + HttpDateUtils.format(Instant.now())
                        + "\r\n\r\n");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
    }

    @Test
    void shouldRaiseAlertStoreAndCacheableWhenStatusNonCacheableByDefaultAndExpiryDateGiven()
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
    void shouldRaiseAlertStoreAndCacheableWhenStatusNonCacheableByDefaultAndCacheIsPublic()
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
    void shouldRaiseAlertStoreAndCacheableWhenStatusNonCacheableByDefaultAndMaxAgeGiven()
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
    void shouldRaiseAlertStoreAndCacheableWhenStatusNonCacheableByDefaultAndS_MaxAgeGiven()
            throws URIException, HttpMalformedHeaderException {
        // Given
        HttpMessage msg = createMessage();
        msg.setResponseHeader("HTTP/1.1 207 OK\r\n" + "Cache-Control: s-maxage=100");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertStoreAndCacheable("s-maxage=100");
    }

    @ParameterizedTest
    @ValueSource(
            strings = {"200", "203", "204", "206", "300", "301", "404", "405", "410", "414", "501"})
    void shouldRaiseAlertStoreAndCacheableWhenStatusCacheableByDefault(String statusCode)
            throws URIException, HttpMalformedHeaderException {
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
    void shouldRaiseAlertStoreAndCacheableWhenAuthorizationNeededAndCacheMustRevalidated()
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
    void shouldRaiseAlertStoreAndCacheableWhenAuthorizationNeededAndCacheIsPublic()
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
    void shouldRaiseAlertStoreAndCacheableWhenAuthorizationNeededAndS_MaxAgeCacheGiven()
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
    void shouldRaiseAlertStoreAndCacheableWhenCacheIsFreshAndS_MaxAgeDirectiveIsSet()
            throws URIException, HttpMalformedHeaderException {
        // Given
        HttpMessage msg = createMessage();
        msg.setResponseHeader("HTTP/1.1 200 OK\r\n" + "Cache-Control: s-maxage=100, public");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertStoreAndCacheable("s-maxage=100");
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "max-age=100,public",
                "max-age=100,",
                "public,max-age=100,",
                "max-age=100 ,public",
                "max-age=100 , public",
                "max-age=100, public"
            })
    void shouldRaiseAlertStoreAndCacheableWhenCacheIsFreshAndMaxAgeDirectiveIsSet(String value)
            throws URIException, HttpMalformedHeaderException {
        // Given
        HttpMessage msg = createMessage();
        msg.setResponseHeader("HTTP/1.1 200 OK\r\n" + "Cache-Control: " + value);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertStoreAndCacheable("max-age=100");
    }

    @Test
    void shouldRaiseAlertStoreAndCacheableWhenCacheIsFreshAndExpirySpecified()
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
    void shouldRaiseAlertStoreAndCacheableCacheIsFreshWhenNoLifetimeSpecified()
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
                                "pscanbeta.storablecacheable.otherinfo.liberallifetimeheuristic")));
    }

    @Test
    void shouldRaiseAlertStoreAndCacheableWhenStaleRetrieveAllowed()
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
