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
package org.zaproxy.addon.retire;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.retire.model.Repo;

public class RetireScanRuleUnitTest extends PassiveScannerTest<RetireScanRule> {

    @Override
    protected RetireScanRule createScanner() {
        RetireScanRule rsr = new RetireScanRule();
        try {
            rsr.setRepo(new Repo("/org/zaproxy/addon/retire/testrepository.json"));
        } catch (IOException e) {
            // Nothing to do
        }
        return rsr;
    }

    @Test
    public void shouldRaiseAlertOnVulnerableUrl() {
        // Given
        HttpMessage msg =
                createMessage("http://example.com/ajax/libs/angularjs/1.2.19/angular.min.js", null);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(1, alertsRaised.size());
        assertTrue(alertsRaised.get(0).getEvidence().contentEquals("/1.2.19/angular.min.js"));
    }

    @Test
    public void shouldRaiseAlertOnVulnerableFilename() {
        // Given
        HttpMessage msg =
                createMessage("http://example.com/CommonElements/js/jquery-3.1.1.min.js", null);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(1, alertsRaised.size());
        assertTrue(alertsRaised.get(0).getEvidence().contentEquals("jquery-3.1.1.min.js"));
    }

    @Test
    public void shouldRaiseAlertOnVulnerableContent() {
        // Given
        String content =
                "/*!\n"
                        + " * Bootstrap v3.3.7 (http://getbootstrap.com)\n"
                        + " * Copyright 2011-2016 Twitter, Inc.\n"
                        + " * Licensed under the MIT license\n"
                        + " */";
        HttpMessage msg = createMessage("http://example.com/angular.min.js", content);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(1, alertsRaised.size());
        assertTrue(alertsRaised.get(0).getEvidence().equals("* Bootstrap v3.3.7"));
    }

    @Test
    public void shouldRaiseAlertOnHashOfVulnerableContent() {
        // Given
        String content =
                "/*!\n"
                        + " * Hash test content v0.0.1\n"
                        + " * Copyright 2011-2016 Null, Inc.\n"
                        + " * Licensed under the MIT license\n"
                        + " */";
        HttpMessage msg = createMessage("http://example.com/hash.js", content);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(1, alertsRaised.size());
        assertTrue(
                alertsRaised
                        .get(0)
                        .getOtherInfo()
                        .equals(
                                "* http://example.com/hash-test-entry\n"
                                        + "The library matched the known vulnerable hash e19cea51d7542303f6e8949a0ae27dd3509ea566."));
    }

    @Test
    public void shouldNotRaiseAlertOnDontCheckUrl() {
        // Given
        HttpMessage msg = createMessage("https://www.google-analytics.com/ga.js", null);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(0, alertsRaised.size());
    }

    private HttpMessage createMessage(String url, String body) {
        HttpMessage msg = new HttpMessage();
        if (url == null) {
            url = "http://example.com/";
        }
        if (body == null) {
            body = "<html><head></head><body><H1>Some Heading</H1></body></html>";
        }
        HttpRequestHeader requestHeader = new HttpRequestHeader();
        try {
            requestHeader.setURI(new URI(url, false));
        } catch (URIException | NullPointerException e) {
            // Nothing to do
        }
        msg = new HttpMessage();
        msg.setRequestHeader(requestHeader);
        try {
            msg.setResponseHeader("HTTP/1.1 200 OK\r\n");
        } catch (HttpMalformedHeaderException e) {
            // Nothing to do
        }
        msg.setResponseBody(body);

        return msg;
    }
}
