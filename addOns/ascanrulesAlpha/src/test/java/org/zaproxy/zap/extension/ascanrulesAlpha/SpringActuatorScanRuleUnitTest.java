/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.zap.extension.ascanrulesAlpha;

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;

import fi.iki.elonen.NanoHTTPD;
import fi.iki.elonen.NanoHTTPD.Response;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;
import org.zaproxy.zap.testutils.NanoServerHandler;

/** Unit test for {@link SpringActuatorScanRule}. */
class SpringActuatorScanRuleUnitTest extends ActiveScannerTest<SpringActuatorScanRule> {

    private static final String ACTUATOR_CONTENT_TYPE =
            "Content-Type: application/vnd.spring-boot.actuator.v2+json;charset=UTF-8";
    private static final String RELEVANT_BODY = "{\"status\":\"UP\"}";
    private static final String IRRELEVANT_BODY = "<body><h1>Howdy></h1></body>";
    private static final String REQ_PATH = "actuator/health";

    @Override
    protected SpringActuatorScanRule createScanner() {
        return new SpringActuatorScanRule();
    }

    @Test
    void shouldTargetSpringTech() {
        // Given
        TechSet techSet = techSet(Tech.SPRING);
        // When
        boolean targets = rule.targets(techSet);
        // Then
        assertThat(targets, is(equalTo(true)));
    }

    @Test
    void shouldNotTargetNonSpringTechs() {
        // Given
        TechSet techSet = techSetWithout(Tech.SPRING);
        // When
        boolean targets = rule.targets(techSet);
        // Then
        assertThat(targets, is(equalTo(false)));
    }

    @Test
    void shouldBeInfoGatherAlert() {
        // Given
        Integer category = Category.INFO_GATHER;
        // When
        Integer ruleCategory = rule.getCategory();
        // Then
        assertEquals(ruleCategory, category);
    }

    @Test
    void shouldScanMessageWithoutPath() throws HttpMalformedHeaderException {
        // Given
        String path = "";
        this.nano.addHandler(
                new NanoServerHandler(path) {
                    @Override
                    protected Response serve(NanoHTTPD.IHTTPSession session) {
                        return newFixedLengthResponse(
                                Response.Status.OK, NanoHTTPD.MIME_HTML, RELEVANT_BODY);
                    }
                });
        HttpMessage msg = getHttpMessage(path);
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
        assertThat(httpMessagesSent, hasSize(2));
    }

    @Test
    void shouldScanResponseWithoutContentType() throws HttpMalformedHeaderException {
        // Given
        String servePath = "";
        String alertPath = REQ_PATH;
        this.nano.addHandler(
                new NanoServerHandler("/" + alertPath) {
                    @Override
                    protected Response serve(NanoHTTPD.IHTTPSession session) {
                        return newFixedLengthResponse(Response.Status.OK, null, RELEVANT_BODY);
                    }
                });
        HttpMessage msg = this.getHttpMessage(servePath);
        rule.init(msg, this.parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
        assertThat(httpMessagesSent, hasSize(2));
    }

    @Test
    void shouldHandleNetworkErrors() throws HttpMalformedHeaderException {
        // Given
        String path = "/";
        this.nano.addHandler(
                new NanoServerHandler(path) {
                    @Override
                    protected Response serve(NanoHTTPD.IHTTPSession session) {
                        return newFixedLengthResponse(
                                Response.Status.OK, NanoHTTPD.MIME_HTML, RELEVANT_BODY);
                    }
                });
        HttpMessage msg = getHttpMessage(path);
        rule.init(msg, parent);
        this.nano.stop();
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
        assertThat(httpMessagesSent, hasSize(0));
    }

    @ParameterizedTest
    @ValueSource(strings = {ACTUATOR_CONTENT_TYPE, "Content-Type: application/json"})
    void shouldAlertWhenScanMessageWithoutPathAndRelevantContent(String contentType)
            throws HttpMalformedHeaderException {
        // Given
        String servePath = "";
        String alertPath = REQ_PATH;
        this.nano.addHandler(
                new NanoServerHandler("/" + alertPath) {
                    @Override
                    protected Response serve(NanoHTTPD.IHTTPSession session) {
                        return newFixedLengthResponse(
                                Response.Status.OK, contentType, RELEVANT_BODY);
                    }
                });
        HttpMessage msg = this.getHttpMessage(servePath);
        rule.init(msg, this.parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(httpMessagesSent, hasSize(1));
        Alert alert = alertsRaised.get(0);
        assertEquals(Alert.RISK_MEDIUM, alert.getRisk());
        assertEquals(Alert.CONFIDENCE_MEDIUM, alert.getConfidence());
        assertEquals(rule.getName(), alert.getName());
        assertEquals(rule.getWascId(), alert.getWascId());
    }

    @Test
    void shouldSendGetRequestWhenOriginalRequestWasNotGet() throws HttpMalformedHeaderException {
        // Given
        String path = "";
        HttpMessage msg = getHttpMessage(path);
        msg.getRequestHeader().setMethod(HttpRequestHeader.POST);
        msg.getRequestHeader().addHeader(HttpHeader.CONTENT_TYPE, ACTUATOR_CONTENT_TYPE);
        msg.setRequestBody("field1=value1&field2=value2");
        rule.init(msg, parent);

        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(2));
        assertEquals(HttpRequestHeader.GET, httpMessagesSent.get(0).getRequestHeader().getMethod());
        assertEquals(0, httpMessagesSent.get(0).getRequestBody().length());
    }

    @ParameterizedTest
    @ValueSource(strings = {ACTUATOR_CONTENT_TYPE, "Content-Type: application/json"})
    void shouldAlertIfTestedUrlRespondsOKWithRelevantContent(String contentType)
            throws HttpMalformedHeaderException {
        // Given
        String servePath = "/shouldAlert";
        String alertPath = REQ_PATH;
        this.nano.addHandler(
                new NanoServerHandler(servePath) {
                    @Override
                    protected Response serve(NanoHTTPD.IHTTPSession session) {
                        return newFixedLengthResponse(
                                Response.Status.OK, NanoHTTPD.MIME_HTML, IRRELEVANT_BODY);
                    }
                });
        this.nano.addHandler(
                new NanoServerHandler("/" + alertPath) {
                    @Override
                    protected Response serve(NanoHTTPD.IHTTPSession session) {
                        return newFixedLengthResponse(
                                Response.Status.OK, contentType, RELEVANT_BODY);
                    }
                });
        HttpMessage msg = this.getHttpMessage(servePath);
        rule.init(msg, this.parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(httpMessagesSent, hasSize(1));
        Alert alert = alertsRaised.get(0);
        assertEquals(Alert.RISK_MEDIUM, alert.getRisk());
        assertEquals(Alert.CONFIDENCE_MEDIUM, alert.getConfidence());
        assertEquals(rule.getName(), alert.getName());
        assertEquals(rule.getWascId(), alert.getWascId());
    }

    @Test
    void shouldNotAlertIfTestedUrlRespondsOKWithIrrelevantContent()
            throws HttpMalformedHeaderException {
        // Given
        String servePath = "/randomPath";
        String alertPath = REQ_PATH;
        this.nano.addHandler(
                new NanoServerHandler(servePath) {
                    @Override
                    protected Response serve(NanoHTTPD.IHTTPSession session) {
                        return newFixedLengthResponse(
                                Response.Status.OK, NanoHTTPD.MIME_HTML, IRRELEVANT_BODY);
                    }
                });
        this.nano.addHandler(
                new NanoServerHandler("/" + alertPath) {
                    @Override
                    protected Response serve(NanoHTTPD.IHTTPSession session) {
                        return newFixedLengthResponse(
                                Response.Status.OK, ACTUATOR_CONTENT_TYPE, IRRELEVANT_BODY);
                    }
                });
        HttpMessage msg = this.getHttpMessage(servePath);
        rule.init(msg, this.parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
        assertThat(httpMessagesSent, hasSize(2));
    }

    @Test
    void shouldNotAlertIfTestedUrlRespondsOKWithIrrelevantHeader()
            throws HttpMalformedHeaderException {
        // Given
        String servePath = "/randomPath";
        String alertPath = REQ_PATH;
        this.nano.addHandler(
                new NanoServerHandler(servePath) {
                    @Override
                    protected Response serve(NanoHTTPD.IHTTPSession session) {
                        return newFixedLengthResponse(
                                Response.Status.OK, NanoHTTPD.MIME_HTML, IRRELEVANT_BODY);
                    }
                });
        this.nano.addHandler(
                new NanoServerHandler("/" + alertPath) {
                    @Override
                    protected Response serve(NanoHTTPD.IHTTPSession session) {
                        return newFixedLengthResponse(
                                Response.Status.OK, NanoHTTPD.MIME_HTML, RELEVANT_BODY);
                    }
                });
        HttpMessage msg = this.getHttpMessage(servePath);
        rule.init(msg, this.parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
        assertThat(httpMessagesSent, hasSize(2));
    }

    @ParameterizedTest
    @ValueSource(strings = {ACTUATOR_CONTENT_TYPE, "Content-Type: application/json"})
    void shouldAlertIfTestedNestedUrlRespondsOKWithRelevantHeader(String contentType)
            throws HttpMalformedHeaderException {
        // Given
        String servePath = "/shouldAlert/";
        String alertPath = REQ_PATH;
        String deepPath = servePath + alertPath;
        this.nano.addHandler(
                new NanoServerHandler(deepPath) {
                    @Override
                    protected Response serve(NanoHTTPD.IHTTPSession session) {
                        return newFixedLengthResponse(
                                Response.Status.OK, contentType, RELEVANT_BODY);
                    }
                });
        this.nano.addHandler(
                new NanoServerHandler(servePath) {
                    @Override
                    protected Response serve(NanoHTTPD.IHTTPSession session) {
                        return newFixedLengthResponse(
                                Response.Status.OK, NanoHTTPD.MIME_HTML, IRRELEVANT_BODY);
                    }
                });
        HttpMessage msg = this.getHttpMessage(servePath);
        rule.init(msg, this.parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(httpMessagesSent, hasSize(1));
        Alert alert = alertsRaised.get(0);
        assertEquals(Alert.RISK_MEDIUM, alert.getRisk());
        assertEquals(Alert.CONFIDENCE_MEDIUM, alert.getConfidence());
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        int cwe = rule.getCweId();
        int wasc = rule.getWascId();
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(cwe, is(equalTo(215)));
        assertThat(wasc, is(equalTo(13)));
        assertThat(tags.size(), is(equalTo(3)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A01_BROKEN_AC.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A05_BROKEN_AC.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.WSTG_V42_CONF_05_ENUMERATE_INFRASTRUCTURE.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A01_BROKEN_AC.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A01_BROKEN_AC.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A05_BROKEN_AC.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A05_BROKEN_AC.getValue())));
        assertThat(
                tags.get(CommonAlertTag.WSTG_V42_CONF_05_ENUMERATE_INFRASTRUCTURE.getTag()),
                is(equalTo(CommonAlertTag.WSTG_V42_CONF_05_ENUMERATE_INFRASTRUCTURE.getValue())));
    }
}
