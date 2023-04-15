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
package org.zaproxy.zap.extension.ascanrules;

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;

import fi.iki.elonen.NanoHTTPD;
import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.http.HttpFieldsNames;
import org.zaproxy.zap.testutils.NanoServerHandler;

/** Unit test for {@link CloudMetadataScanRule}. */
class CloudMetadataScanRuleUnitTest extends ActiveScannerTest<CloudMetadataScanRule> {

    @Override
    protected CloudMetadataScanRule createScanner() {
        return new CloudMetadataScanRule();
    }

    @Test
    void shouldNotAlertIfResponseIsNot200Ok() throws Exception {
        // Given
        String path = "/latest/meta-data/";
        String body = "<html><head></head><H>401 - Unauthorized</H1><html>";
        this.nano.addHandler(createHandler(path, Response.Status.UNAUTHORIZED, body, ""));
        HttpMessage msg = this.getHttpMessage(path);
        rule.init(msg, this.parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
        assertThat(httpMessagesSent, is(not(empty())));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "169.254.169.254",
                "aws.zaproxy.org",
                "100.100.100.200",
                "alibaba.zaproxy.org"
            })
    void shouldAlertIfResponseIs200Ok(String host) throws Exception {
        // Given
        String path = "/latest/meta-data/";
        // https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html
        String body = "<html><head></head><H></H1>ami-id\nami-launch-index<html>";
        this.nano.addHandler(createHandler(path, Response.Status.OK, body, host));
        HttpMessage msg = this.getHttpMessage(path);
        rule.init(msg, this.parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        Alert alert = alertsRaised.get(0);
        assertEquals(Alert.RISK_HIGH, alert.getRisk());
        assertEquals(Alert.CONFIDENCE_LOW, alert.getConfidence());
        assertEquals(host, alert.getAttack());
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(tags.size(), is(equalTo(2)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getValue())));
    }

    @Test
    void shouldReturnExpectedExampleAlert() {
        // Given / When
        List<Alert> alerts = rule.getExampleAlerts();
        // Then
        assertThat(alerts.size(), is(equalTo(1)));
        Alert alert1 = alerts.get(0);
        assertThat(alert1.getRisk(), is(equalTo(Alert.RISK_HIGH)));
        assertThat(alert1.getConfidence(), is(equalTo(Alert.CONFIDENCE_LOW)));
    }

    private static NanoServerHandler createHandler(
            String path, Response.Status status, String body, String host) {
        return new NanoServerHandler(path) {
            @Override
            protected Response serve(IHTTPSession session) {
                if (session.getHeaders().get(HttpFieldsNames.HOST).equals(host) || host.isEmpty()) {
                    return newFixedLengthResponse(status, NanoHTTPD.MIME_HTML, body);
                }
                return newFixedLengthResponse(Response.Status.NOT_FOUND, NanoHTTPD.MIME_HTML, "");
            }
        };
    }
}
