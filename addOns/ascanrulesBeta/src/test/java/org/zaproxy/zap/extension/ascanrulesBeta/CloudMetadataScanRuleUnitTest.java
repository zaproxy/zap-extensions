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
package org.zaproxy.zap.extension.ascanrulesBeta;

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
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
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
        this.nano.addHandler(
                createHandler(
                        path,
                        newFixedLengthResponse(
                                Response.Status.UNAUTHORIZED, NanoHTTPD.MIME_HTML, body),
                        ""));
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
                "169.154.169.254",
                "aws.zaproxy.org",
                "100.100.100.200",
                "alibaba.zaproxy.org"
            })
    void shouldAlertIfResponseIs200Ok(String host) throws Exception {
        // Given
        String path = "/latest/meta-data/";
        // https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html
        String body = "<html><head></head><H></H1>ami-id\nami-launch-index<html>";
        this.nano.addHandler(
                createHandler(
                        path,
                        newFixedLengthResponse(Response.Status.OK, NanoHTTPD.MIME_HTML, body),
                        host));
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

    private static NanoServerHandler createHandler(String path, Response response, String host) {
        return new NanoServerHandler(path) {
            @Override
            protected Response serve(IHTTPSession session) {
                if (session.getHeaders().get("host").startsWith(host) || host.isEmpty()) {
                    return response;
                }
                return newFixedLengthResponse(Response.Status.NOT_FOUND, NanoHTTPD.MIME_HTML, "");
            }
        };
    }
}
