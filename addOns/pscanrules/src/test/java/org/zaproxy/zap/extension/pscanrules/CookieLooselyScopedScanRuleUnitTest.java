/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP Development Team
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
package org.zaproxy.zap.extension.pscanrules;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpResponseHeader;

/** @author Vahid Rafiei (@vahid_r) */
public class CookieLooselyScopedScanRuleUnitTest
        extends PassiveScannerTest<CookieLooselyScopedScanRule> {

    @Override
    protected CookieLooselyScopedScanRule createScanner() {
        return new CookieLooselyScopedScanRule();
    }

    private HttpMessage createBasicMessage() throws HttpMalformedHeaderException {
        HttpMessage msg = new HttpMessage();
        msg.setResponseHeader("HTTP/1.1 200 OK\r\n" + "Server: Apache-Coyote/1.1\r\n");

        return msg;
    }

    @Test
    public void shouldNotRaiseAlertIfThereIsNoCookieInResponseHeader() throws Exception {
        // Given
        HttpMessage msg = createBasicMessage();
        msg.setRequestHeader("GET /admin/roles/ HTTP/1.1");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), is(0));
    }

    @Test
    public void shouldNotRaiseAlertIfCookieDomainIsNotSet() throws Exception {
        // Given
        HttpMessage msg = createBasicMessage();
        msg.setRequestHeader("GET /admin/roles/ HTTP/1.1");
        msg.getResponseHeader().setHeader(HttpResponseHeader.SET_COOKIE, "a=b;domain=");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), is(0));
    }

    @Test
    public void shouldNotRaiseAlertIfHostDomainStartsWithDotAndCookieDomainIsNotSet()
            throws Exception {
        // Given
        HttpMessage msg = createBasicMessage();
        msg.setRequestHeader("GET .local.test.com HTTP/1.1");
        msg.getResponseHeader().setHeader(HttpResponseHeader.SET_COOKIE, "a=b;");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), is(0));
    }

    @Test
    public void shouldRaiseAlertIfHostDomainIsDifferentFromCookieDomain() throws Exception {
        // Given
        HttpMessage msg = createBasicMessage();
        msg.setRequestHeader("GET http://dev.test.org HTTP/1.1");
        msg.getResponseHeader()
                .setHeader(HttpResponseHeader.SET_COOKIE, "a=b;domain=local.yahoo.com;");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), is(1));
    }

    @Test
    public void shouldDomainComparisonBeCaseInsensitive() throws Exception {
        // Given
        HttpMessage msg = createBasicMessage();
        msg.setRequestHeader("GET http://TesT.org HTTP/1.1");
        msg.getResponseHeader().setHeader(HttpResponseHeader.SET_COOKIE, "a=b;domain=tEst.org;");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), is(0));
    }

    @Test
    public void
            shouldNotRaiseAlertIfHostDomainAndCookieDomainAreTheSameAndDomainsAreNotSecondLevel()
                    throws Exception {
        // Given
        HttpMessage msg = createBasicMessage();
        msg.setRequestHeader("GET http://test.example.com HTTP/1.1");
        msg.getResponseHeader()
                .setHeader(HttpResponseHeader.SET_COOKIE, "a=b;domain=test.example.com;");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), is(0));
    }

    @Test
    public void shouldRaiseAlertIfHostDomainHasMoreSubDomainsThanCookieDomain() throws Exception {
        // Given
        HttpMessage msg = createBasicMessage();
        msg.setRequestHeader("GET http://test.example.com HTTP/1.1");
        msg.getResponseHeader().setHeader(HttpResponseHeader.SET_COOKIE, "a=b;domain=example.com;");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), is(1));
    }

    @Test
    public void shouldNotRaiseAlertIfHostDomainHasLessSubDomainsThanCookieDomain()
            throws Exception {
        // Given
        HttpMessage msg = createBasicMessage();
        msg.setRequestHeader("GET http://example.com HTTP/1.1");
        msg.getResponseHeader()
                .setHeader(HttpResponseHeader.SET_COOKIE, "a=b;domain=stage.example.com;");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), is(0));
    }

    @Test
    public void shouldRaiseAlertIfRightMostDomainsMatch() throws Exception {
        // Given
        HttpMessage msg = createBasicMessage();
        msg.setRequestHeader("GET http://test.example.com/admin/roles HTTP/1.1");
        msg.getResponseHeader().setHeader(HttpResponseHeader.SET_COOKIE, "a=b;domain=.example.com");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), is(1));
    }

    @Test
    public void shouldScanCookieDomainWithJustTld() throws Exception {
        // Given
        HttpMessage msg = createBasicMessage();
        msg.setRequestHeader("GET http://example.com/ HTTP/1.1");
        msg.getResponseHeader().setHeader(HttpResponseHeader.SET_COOKIE, "a=b;domain=com");

        // When / Then
        assertDoesNotThrow(() -> scanHttpResponseReceive(msg));
    }

    @Test
    public void shouldScanHostWithoutTld() throws Exception {
        // Given
        HttpMessage msg = createBasicMessage();
        msg.setRequestHeader("GET http://intranet/ HTTP/1.1");
        msg.getResponseHeader()
                .setHeader(HttpResponseHeader.SET_COOKIE, "a=b;domain=subdomain.intranet");

        // When / Then
        assertDoesNotThrow(() -> scanHttpResponseReceive(msg));
    }
}
