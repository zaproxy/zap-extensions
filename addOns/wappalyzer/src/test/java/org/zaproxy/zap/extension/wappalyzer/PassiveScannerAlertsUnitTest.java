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
package org.zaproxy.zap.extension.wappalyzer;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

import java.util.Collections;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.testutils.PassiveScannerTestUtils;

class PassiveScannerAlertsUnitTest extends PassiveScannerTestUtils<WappalyzerPassiveScanner> {

    ApplicationTestHolder defaultHolder;

    public ApplicationTestHolder getDefaultHolder() {
        if (defaultHolder == null) {
            try {
                defaultHolder = new ApplicationTestHolder();
                WappalyzerJsonParser parser = new WappalyzerJsonParser();
                WappalyzerData result =
                        parser.parse(
                                "categories.json", Collections.singletonList("apps.json"), true);
                defaultHolder.setApplications(result.getApplications());
            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }
        }
        return defaultHolder;
    }

    @Override
    protected void setUpMessages() {
        mockMessages(new ExtensionWappalyzer());
    }

    @Override
    protected WappalyzerPassiveScanner createScanner() {
        getDefaultHolder().resetApplicationsToSite();
        return new WappalyzerPassiveScanner(getDefaultHolder());
    }

    @Test
    void shouldHaveCpeAndVersionInAlertIfAvailable() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test HTTP/1.1");
        msg.getResponseHeader().addHeader("Server", "Apache/2.4.7 (Ubuntu)");
        // When
        Application app = new Application();
        app.setCpe("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*");
        ApplicationMatch appMatch = new ApplicationMatch(app);
        appMatch.addVersion("2.4.7");
        Alert alert = rule.createAlert(msg, appMatch);
        // Then
        assertThat(
                alert.getOtherInfo(),
                is(
                        equalTo(
                                "The following CPE is associated with the identified tech: cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*\n"
                                        + "The following version(s) is/are associated with the identified tech: 2.4.7")));
        assertThat(alert.getWascId(), is(equalTo(13)));
        assertThat(alert.getCweId(), is(equalTo(200)));
    }

    @Test
    void shouldNotHaveCpeAndVersionInAlertIfNotAvailablet() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test HTTP/1.1");
        msg.getResponseHeader().addHeader("Server", "Apache/2.4.7 (Ubuntu)");
        // When
        Application app = new Application();
        ApplicationMatch appMatch = new ApplicationMatch(app);
        Alert alert = rule.createAlert(msg, appMatch);
        // Then
        assertThat(alert.getOtherInfo(), is(equalTo("")));
        assertThat(alert.getReference(), is(equalTo("")));
        assertThat(alert.getWascId(), is(equalTo(13)));
        assertThat(alert.getCweId(), is(equalTo(200)));
    }

    @Test
    void shouldHaveRefInAlertIfWebsiteAvailable() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test HTTP/1.1");
        msg.getResponseHeader().addHeader("Server", "Apache/2.4.7 (Ubuntu)");
        // When
        Application app = new Application();
        app.setWebsite("https://httpd.apache.org");
        ApplicationMatch appMatch = new ApplicationMatch(app);
        Alert alert = rule.createAlert(msg, appMatch);
        // Then
        assertThat(alert.getOtherInfo(), is(equalTo("")));
        assertThat(alert.getReference(), is(equalTo("https://httpd.apache.org")));
        assertThat(alert.getWascId(), is(equalTo(13)));
        assertThat(alert.getCweId(), is(equalTo(200)));
    }
}
