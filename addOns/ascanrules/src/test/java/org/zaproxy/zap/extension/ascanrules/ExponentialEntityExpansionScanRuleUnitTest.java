/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

import fi.iki.elonen.NanoHTTPD;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.addon.commonlib.http.HttpFieldsNames;
import org.zaproxy.zap.testutils.NanoServerHandler;

class ExponentialEntityExpansionScanRuleUnitTest
        extends ActiveScannerTest<ExponentialEntityExpansionScanRule> {

    private static final String GENERIC_RESPONSE =
            "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n"
                    + "<html><head></head><body></body></html>";

    @Override
    protected ExponentialEntityExpansionScanRule createScanner() {
        return new ExponentialEntityExpansionScanRule();
    }

    @ParameterizedTest
    @ValueSource(
            strings = {"application/xml", "text/xml", "image/svg+xml", "application/xhtml+xml"})
    void shouldSendXmlPayloadToXmlAcceptingEndpoints(String contentType) throws Exception {
        // Given
        String path = "/endpoint/";
        nano.addHandler(new OkResponse(path));
        HttpMessage msg = this.getHttpMessage(path);
        msg.getRequestHeader().setHeader(HttpFieldsNames.CONTENT_TYPE, contentType);
        rule.init(msg, this.parent);
        // When
        rule.scan();
        // Then
        assertThat(countMessagesSent, is(1));
        assertThat(
                httpMessagesSent.get(0).getRequestBody().toString(),
                is(ExponentialEntityExpansionScanRule.XML_PAYLOAD));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "text/vnd.yaml",
                "text/yml",
                "text/yaml",
                "text/x-yaml",
                "application/x-yaml",
                "application/x-yml"
            })
    void shouldSendYamlPayloadToYamlAcceptingEndpoints(String contentType) throws Exception {
        // Given
        String path = "/endpoint/";
        nano.addHandler(new OkResponse(path));
        HttpMessage msg = this.getHttpMessage(path);
        msg.getRequestHeader().setHeader(HttpFieldsNames.CONTENT_TYPE, contentType);
        rule.init(msg, this.parent);
        // When
        rule.scan();
        // Then
        assertThat(countMessagesSent, is(1));
        assertThat(
                httpMessagesSent.get(0).getRequestBody().toString(),
                is(ExponentialEntityExpansionScanRule.YAML_PAYLOAD));
    }

    @ParameterizedTest
    @ValueSource(strings = {"text/plain", "application/json", "text/html"})
    void shouldNotAttackNonXmlOrYamlAcceptingEndpoints(String contentType) throws Exception {
        // Given
        String path = "/endpoint/";
        nano.addHandler(new OkResponse(path));
        HttpMessage msg = this.getHttpMessage(path);
        msg.getRequestHeader().setHeader(HttpFieldsNames.CONTENT_TYPE, contentType);
        rule.init(msg, this.parent);
        // When
        rule.scan();
        // Then
        assertThat(countMessagesSent, is(0));
    }

    @Test
    void shouldNotAttackEndpointsWithoutContentTypeHeader() throws Exception {
        // Given
        String path = "/endpoint/";
        nano.addHandler(new OkResponse(path));
        HttpMessage msg = this.getHttpMessage(path);
        rule.init(msg, this.parent);
        // When
        rule.scan();
        // Then
        assertThat(countMessagesSent, is(0));
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        int cwe = rule.getCweId();
        int wasc = rule.getWascId();
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(cwe, is(equalTo(776)));
        assertThat(wasc, is(equalTo(44)));
        assertThat(tags.size(), is(equalTo(7)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A04_INSECURE_DESIGN.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.WSTG_V42_BUSL_09_UPLOAD_MALICIOUS_FILES.getTag()),
                is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.QA_CICD.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.QA_STD.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.QA_FULL.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.API.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.PENTEST.getTag()), is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A04_INSECURE_DESIGN.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A04_INSECURE_DESIGN.getValue())));
        assertThat(
                tags.get(CommonAlertTag.WSTG_V42_BUSL_09_UPLOAD_MALICIOUS_FILES.getTag()),
                is(equalTo(CommonAlertTag.WSTG_V42_BUSL_09_UPLOAD_MALICIOUS_FILES.getValue())));
    }

    private static class OkResponse extends NanoServerHandler {
        public OkResponse(String path) {
            super(path);
        }

        @Override
        protected NanoHTTPD.Response serve(NanoHTTPD.IHTTPSession session) {
            consumeBody(session);
            return newFixedLengthResponse(
                    NanoHTTPD.Response.Status.OK, "text/html", GENERIC_RESPONSE);
        }
    }
}
