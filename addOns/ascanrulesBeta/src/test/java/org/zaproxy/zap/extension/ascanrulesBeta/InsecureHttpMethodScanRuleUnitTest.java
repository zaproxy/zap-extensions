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
package org.zaproxy.zap.extension.ascanrulesBeta;

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;

import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Method;
import fi.iki.elonen.NanoHTTPD.Response;
import fi.iki.elonen.NanoHTTPD.Response.Status;
import java.util.Map;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.zap.testutils.NanoServerHandler;

class InsecureHttpMethodScanRuleUnitTest extends ActiveScannerTest<InsecureHttpMethodScanRule> {

    @Override
    protected InsecureHttpMethodScanRule createScanner() {
        return new InsecureHttpMethodScanRule();
    }

    private static class PutPatchNanoServerHandler extends NanoServerHandler {

        String contentType;
        String method;
        int status;

        PutPatchNanoServerHandler(int status, String method, String contentType, String path) {
            super(path);
            this.status = status;
            this.method = method;
            this.contentType = contentType;
        }

        @Override
        protected Response serve(IHTTPSession session) {
            Response response = newFixedLengthResponse("");

            if (session.getMethod().equals(Method.OPTIONS)) {
                response.addHeader("Allow", method);
                return response;
            }

            if (session.getMethod().equals(Method.PUT)
                    || session.getMethod().equals(Method.PATCH)) {
                response.setMimeType(contentType);
                response.setStatus(Status.lookup(status));
                return response;
            }
            consumeBody(session);
            return response;
        }
    }

    @ParameterizedTest
    @CsvSource({"PUT, json", "PUT, xml", "PATCH, json", "PATCH, xml"})
    void shouldNotRaiseAlertsForPutOrPatchMethodsIfReturnJsonOrXml200StatusNonLowThreshold(
            String method, String contentType) throws Exception {
        // Given
        String path = "/";
        HttpMessage message = getHttpMessage(path);
        nano.addHandler(new PutPatchNanoServerHandler(200, method, contentType, path));

        rule.init(message, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Disabled
    @ParameterizedTest
    @ValueSource(strings = {"PUT", "PATCH"})
    void shouldRaiseAlertForPutOrPatchMethodsIfNotReturnJsonOrXml200StatusNonLowThreshold(
            String method) throws Exception {
        // Given
        String path = "/";
        String contentType = "html";
        HttpMessage message = getHttpMessage(path);
        nano.addHandler(new PutPatchNanoServerHandler(200, method, contentType, path));

        rule.init(message, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getName(), equalTo("Insecure HTTP Method - " + method));
        assertThat(alertsRaised.get(0).getEvidence(), is(equalTo("200")));
        assertThat(
                alertsRaised.get(0).getOtherInfo(),
                is(
                        equalTo(
                                "See the discussion on stackexchange: https://security.stackexchange.com/questions/21413/how-to-exploit-http-methods, for understanding REST operations see https://www.restapitutorial.com/lessons/httpmethods.html")));
    }

    @ParameterizedTest
    @CsvSource({"PUT, json", "PUT, xml", "PATCH, json", "PATCH, xml"})
    void shouldNotRaiseAlertsForPutOrPatchMethodsIfReturnJsonOrXml403StatusNonLowThreshold(
            String method, String contentType) throws Exception {
        // Given
        String path = "/";
        HttpMessage message = getHttpMessage(path);
        nano.addHandler(new PutPatchNanoServerHandler(200, method, contentType, path));

        rule.init(message, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, is(empty()));
    }

    @Disabled
    @ParameterizedTest
    @ValueSource(strings = {"PUT", "PATCH"})
    void shouldNotRaiseAlertForPutOrPatchMethodsIfNotReturnJsonOrXml403StatusNonLowThreshold(
            String method) throws Exception {
        // Given
        String path = "/";
        String contentType = "html";
        HttpMessage message = getHttpMessage(path);
        nano.addHandler(new PutPatchNanoServerHandler(403, method, contentType, path));

        rule.init(message, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, is(empty()));
    }

    @ParameterizedTest
    @ValueSource(strings = {"PUT", "PATCH"})
    void shouldRaiseAlertForPutOrPatchMethodsIfNotReturnJsonOrXml403StatusAtLowThreshold(
            String method) throws Exception {
        // Given
        String path = "/";
        String contentType = "html";
        HttpMessage message = getHttpMessage(path);
        nano.addHandler(new PutPatchNanoServerHandler(403, method, contentType, path));

        rule.init(message, parent);
        rule.setAlertThreshold(AlertThreshold.LOW);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(
                alertsRaised.get(0).getOtherInfo(),
                is(
                        equalTo(
                                "The OPTIONS method disclosed the following enabled HTTP methods for this resource: [%s]"
                                        .formatted(method))));
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        int cwe = rule.getCweId();
        int wasc = rule.getWascId();
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(cwe, is(equalTo(749)));
        assertThat(wasc, is(equalTo(45)));
        assertThat(tags.size(), is(equalTo(6)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.WSTG_V42_CONF_06_HTTP_METHODS.getTag()),
                is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.DEV_FULL.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.QA_FULL.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.PENTEST.getTag()), is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getValue())));
        assertThat(
                tags.get(CommonAlertTag.WSTG_V42_CONF_06_HTTP_METHODS.getTag()),
                is(equalTo(CommonAlertTag.WSTG_V42_CONF_06_HTTP_METHODS.getValue())));
    }
}
