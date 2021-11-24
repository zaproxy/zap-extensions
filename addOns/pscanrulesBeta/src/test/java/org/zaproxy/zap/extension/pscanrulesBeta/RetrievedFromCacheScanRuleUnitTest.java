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

import java.util.Map;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.commonlib.CommonAlertTag;

class RetrievedFromCacheScanRuleUnitTest extends PassiveScannerTest<RetrievedFromCacheScanRule> {

    private static final String X_CACHE = "X-Cache";
    private static final String AGE = "Age";

    private HttpMessage createMessage() throws URIException {
        HttpRequestHeader requestHeader = new HttpRequestHeader();
        requestHeader.setURI(new URI("http://example.com", false));

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(requestHeader);
        return msg;
    }

    @Override
    protected RetrievedFromCacheScanRule createScanner() {
        return new RetrievedFromCacheScanRule();
    }

    @Test
    void scannerNameShouldMatch() {
        // Quick test to verify scan rule name which is used in the policy dialog but not
        // alerts

        // Given
        RetrievedFromCacheScanRule thisScanner = createScanner();
        // Then
        assertThat(thisScanner.getName(), equalTo("Retrieved from Cache"));
    }

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
    void shouldNotRaiseAlertIfResponseHasNoRelevantHeader() throws URIException {
        // Given
        HttpMessage msg = createMessage();
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldNotRaiseAlertIfXCacheWasMiss() throws URIException {
        // Given
        String xCacheValue = "MISS";
        HttpMessage msg = createMessage();
        msg.getResponseHeader().addHeader(X_CACHE, xCacheValue);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldNotRaiseAlertIfXCacheWasEmpty() throws URIException {
        // Given
        HttpMessage msg = createMessage();
        msg.getResponseHeader().addHeader(X_CACHE, "");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldRaiseAlertIfXCacheWasHit() throws URIException {
        // Given
        String xCacheValue = "HIT";
        HttpMessage msg = createMessage();
        msg.getResponseHeader().addHeader(X_CACHE, xCacheValue);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo(xCacheValue));
    }

    @Test
    void shouldRaiseAlertIfXCacheWasHitWithServerDetails() throws URIException {
        // Given
        String xCacheValue = "HIT from cache.kolich.local";
        HttpMessage msg = createMessage();
        msg.getResponseHeader().addHeader(X_CACHE, xCacheValue);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo(xCacheValue));
    }

    @Test
    void shouldRaiseAlertIfXCacheWasHitWithMultipleServerDetails() throws URIException {
        // Given
        String xCacheValue = "HIT from proxy.domain.tld, MISS from proxy.local";
        HttpMessage msg = createMessage();
        msg.getResponseHeader().addHeader(X_CACHE, xCacheValue);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo("HIT from proxy.domain.tld"));
    }

    @Test
    void shouldNotRaiseAlertIfAgeWasEmpty() throws URIException {
        // Given
        HttpMessage msg = createMessage();
        msg.getResponseHeader().addHeader(AGE, "");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldRaiseAlertIfAgePresentWithValue() throws URIException {
        // Given
        String ageValue = "24";
        HttpMessage msg = createMessage();
        msg.getResponseHeader().addHeader(AGE, ageValue);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo(AGE + ": " + ageValue));
    }
}
