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

import org.junit.Test;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;

import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.Assert.assertThat;

public class Base64DisclosureTest extends PassiveScannerTest<Base64Disclosure> {

    @Test
    public void shouldIgnoreNonBase64Content() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET / HTTP/1.1");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n" + "X-Custom-Info: NOPE\r\n" + "Set-Cookie: NOPE=NOPE");

        // When
        rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

        // Then
        assertThat(alertsRaised, empty());
    }

    @Test
    public void shouldAlertWhenBase64WithMediumProbability() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET / HTTP/1.1");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "X-Custom-Info: emFwLWV4dGVuc2lvbi1sb25nLi4uLg==\r\n"
                        + "Set-Cookie: NOPE=NOPE");

        // When
        rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

        // Then
        assertThat(alertsRaised, hasSize(1));
    }

    @Test
    public void shouldAlertWhenBase64ContentIsAspNetMACProtectedViewState()
            throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET / HTTP/1.1");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "X-Custom-Info: /wEPDwUJODczNjQ5OTk0D2QWAgIDD2QWAgIFDw8WAh4EV"
                        + "GV4dAUWSSBMb3ZlIERvdG5ldEN1cnJ5LmNvbWRkZMHbBY9JqBTvB5"
                        + "/6kXnY15AUSAwa\r\n"
                        + "Set-Cookie: NOPE=NOPE");

        // When
        rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

        // Then it has only one informational alert
        assertThat(alertsRaised, hasSize(1));
    }

    @Test
    public void shouldAlertWhenBase64ContentIsAspNetUnprotectedViewState()
            throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET / HTTP/1.1");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "X-Custom-Info: /wEPDwUJODczNjQ5OTk0D2QWAgIDD2QWAgIFDw8WAh4EVGV4dAUWSSBMb3ZlIERvdG5ldEN1cnJ5LmNvbWRkZA==\r\n"
                        + "Set-Cookie: NOPE=NOPE");

        // When
        rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

        // Then  it has only one informational and one medium alerts
        assertThat(alertsRaised, hasSize(2));
    }

    // EVENTVALIDATION  :/wEWBALslL0qAu3wv7QBAqnOkfQNAoznisYG

    @Override
    protected Base64Disclosure createScanner() {
        return new Base64Disclosure();
    }
}
