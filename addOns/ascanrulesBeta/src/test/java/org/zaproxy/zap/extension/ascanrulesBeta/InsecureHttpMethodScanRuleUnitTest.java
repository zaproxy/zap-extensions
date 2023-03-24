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
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Method;
import fi.iki.elonen.NanoHTTPD.Response;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.testutils.NanoServerHandler;

class InsecureHttpMethodScanRuleUnitTest extends ActiveScannerTest<InsecureHttpMethodScanRule> {

    @Override
    protected InsecureHttpMethodScanRule createScanner() {
        return new InsecureHttpMethodScanRule();
    }

    private static class AllowedPutPatchNanoServerHandler extends NanoServerHandler {

        String contentType;
        String method;

        AllowedPutPatchNanoServerHandler(String method, String contentType, String path) {
            super(path);
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
                return response;
            }
            consumeBody(session);
            return response;
        }
    }

    @ParameterizedTest
    @CsvSource({"PUT, json", "PUT, xml", "PATCH, json", "PATCH, xml"})
    void shouldRaiseNoAlertsForPutOrPatchMethodsIfReturnJsonOrXml(String method, String contentType)
            throws Exception {
        // Given
        String path = "/shouldRaiseNoAlertsForPutOrPatchMethodsIfReturnJsonOrXml/";
        HttpMessage message = getHttpMessage(path);
        nano.addHandler(new AllowedPutPatchNanoServerHandler(method, contentType, path));

        rule.init(message, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @ParameterizedTest
    @ValueSource(strings = {"PUT", "PATCH"})
    void shouldRaiseAlertForPutOrPatchMethodsIfNotReturnJsonOrXml(String method) throws Exception {
        // Given
        String path = "/shouldRaiseAlertForPutOrPatchMethodsIfNotReturnJsonOrXml/";
        String contentType = "html";
        HttpMessage message = getHttpMessage(path);
        nano.addHandler(new AllowedPutPatchNanoServerHandler(method, contentType, path));

        rule.init(message, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getName(), equalTo("Insecure HTTP Method - " + method));
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        int cwe = rule.getCweId();
        int wasc = rule.getWascId();
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(cwe, is(equalTo(200)));
        assertThat(wasc, is(equalTo(45)));
        assertThat(tags.size(), is(equalTo(3)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.WSTG_V42_CONF_06_HTTP_METHODS.getTag()),
                is(equalTo(true)));
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
