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
package org.zaproxy.zap.extension.ascanrules;

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

import fi.iki.elonen.NanoHTTPD;
import fi.iki.elonen.NanoHTTPD.Response;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.http.HttpFieldsNames;
import org.zaproxy.zap.testutils.NanoServerHandler;

/** Unit test for {@link ExternalRedirectScanRule}. */
class ExternalRedirectScanRuleUnitTest extends ActiveScannerTest<ExternalRedirectScanRule> {

    @Override
    protected ExternalRedirectScanRule createScanner() {
        return new ExternalRedirectScanRule();
    }

    private static final String TYPE_TOKEN = "@@@type@@@";
    private static final String CONTENT_TOKEN = "@@@content@@@";
    private static final String META_TEMPLATE =
            "<html><head><meta http-equiv=\""
                    + TYPE_TOKEN
                    + "\" content=\""
                    + CONTENT_TOKEN
                    + "\"></head><body><H1>Redirect></H1></`body></html>";
    private static final String JS_VAR_TOKEN = "@@@jsVar@@@";
    private static final String JS_VAR_TEMPLATE =
            "<html><head><script>"
                    + JS_VAR_TOKEN
                    + "='"
                    + CONTENT_TOKEN
                    + "';</script></head><body><H1>Redirect></H1></body></html>";
    private static final String JS_METHOD_TOKEN = "@@@jsMethod@@@";
    private static final String JS_METHOD_TEMPLATE =
            "<html><head><script>"
                    + JS_METHOD_TOKEN
                    + "('"
                    + CONTENT_TOKEN
                    + "');</script></head><body><H1>Redirect></H1></body></html>";

    private enum PayloadHandling {
        TRIM,
        ADD,
        NEITHER,
        CONCAT_PARAM,
        CONCAT_PATH
    };

    private NanoServerHandler createHttpRedirectHandler(String path, String header) {
        return createHttpRedirectHandler(path, header, PayloadHandling.NEITHER);
    }

    private NanoServerHandler createHttpRedirectHandler(
            String path, String header, PayloadHandling payloadHandling) {
        return new NanoServerHandler(path) {
            @Override
            protected NanoHTTPD.Response serve(NanoHTTPD.IHTTPSession session) {
                String site = getFirstParamValue(session, "site");
                switch (payloadHandling) {
                    case TRIM:
                        site =
                                site.replaceAll("(?i)https?://", "")
                                        .replaceAll("(?i)https?:\\\\", "")
                                        .replace("\\", "");
                        break;
                    case ADD:
                        site = HttpHeader.SCHEME_HTTP + site;
                        break;
                    case CONCAT_PARAM:
                        site = HttpHeader.SCHEME_HTTPS + "example.com/?q=" + site;
                        break;
                    case CONCAT_PATH:
                        site = HttpHeader.SCHEME_HTTPS + "example.com/" + site;
                        break;
                    case NEITHER:
                    default:
                        // Nothing to do
                }
                if (site != null && site.length() > 0) {
                    Response response =
                            newFixedLengthResponse(
                                    NanoHTTPD.Response.Status.REDIRECT,
                                    NanoHTTPD.MIME_HTML,
                                    "Redirect");
                    response.addHeader(header, site);
                    return response;
                }
                String response = "<html><body></body></html>";
                return newFixedLengthResponse(response);
            }
        };
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        int cwe = rule.getCweId();
        int wasc = rule.getWascId();
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(cwe, is(equalTo(601)));
        assertThat(wasc, is(equalTo(38)));
        assertThat(tags.size(), is(equalTo(3)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A03_INJECTION.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A01_INJECTION.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.WSTG_V42_CLNT_04_OPEN_REDIR.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A03_INJECTION.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A03_INJECTION.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A01_INJECTION.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A01_INJECTION.getValue())));
        assertThat(
                tags.get(CommonAlertTag.WSTG_V42_CLNT_04_OPEN_REDIR.getTag()),
                is(equalTo(CommonAlertTag.WSTG_V42_CLNT_04_OPEN_REDIR.getValue())));
    }

    @Test
    void shouldHaveExpectedExampleAlerts() {
        // Given / When
        List<Alert> alerts = rule.getExampleAlerts();
        // Then
        assertThat(alerts.size(), is(equalTo(4)));
    }

    @Test
    @Override
    public void shouldHaveValidReferences() {
        super.shouldHaveValidReferences();
    }

    @Test
    void shouldHaveHighRisk() {
        // Given / When
        int risk = rule.getRisk();
        // Then
        assertThat(risk, is(equalTo(Alert.RISK_HIGH)));
    }

    @ParameterizedTest
    @ValueSource(strings = {HttpFieldsNames.LOCATION, HttpFieldsNames.REFRESH})
    void shouldReportRedirectWithLocationOrRefreshHeader(String header) throws Exception {
        // Given
        String test = "/";

        nano.addHandler(createHttpRedirectHandler(test, header));
        HttpMessage msg = getHttpMessage(test + "?site=xxx");
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getParam(), equalTo("site"));
        assertThat(alertsRaised.get(0).getEvidence().endsWith(".owasp.org"), equalTo(true));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldNotReportRedirectWithRefreshHeaderWhenPayloadConcatenated(boolean param)
            throws Exception {
        // Given
        String test = "/";

        nano.addHandler(
                param
                        ? createHttpRedirectHandler(
                                test, HttpFieldsNames.REFRESH, PayloadHandling.CONCAT_PARAM)
                        : createHttpRedirectHandler(
                                test, HttpFieldsNames.REFRESH, PayloadHandling.CONCAT_PATH));
        HttpMessage msg = getHttpMessage(test + "?site=xxx");
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldNotReportRedirectWithLocationOrRefreshHeaderIfSchemeIsRemoved() throws Exception {
        // Given
        String test = "/";

        nano.addHandler(
                createHttpRedirectHandler(test, HttpFieldsNames.LOCATION, PayloadHandling.TRIM));
        HttpMessage msg = getHttpMessage(test + "?site=xxx");
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldReportRedirectWithLocationHeaderIfSchemeIsAdded() throws Exception {
        // Given
        String test = "/";

        nano.addHandler(
                createHttpRedirectHandler(test, HttpFieldsNames.LOCATION, PayloadHandling.ADD));
        HttpMessage msg = getHttpMessage(test + "?site=xxx");
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        // Should be payload without scheme
        assertThat(httpMessagesSent.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getAttack().startsWith(HttpHeader.HTTP), equalTo(false));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldNotReportRedirectWithLocationHeaderIfPayloadIsConcatenated(boolean param)
            throws Exception {
        // Given
        String test = "/";
        nano.addHandler(
                param
                        ? createHttpRedirectHandler(
                                test, HttpHeader.LOCATION, PayloadHandling.CONCAT_PARAM)
                        : createHttpRedirectHandler(
                                test, HttpHeader.LOCATION, PayloadHandling.CONCAT_PATH));
        HttpMessage msg = getHttpMessage(test + "?site=xxx");
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldReportDoubleEncodedRedirect() throws Exception {
        // Given
        String test = "/";

        nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected NanoHTTPD.Response serve(NanoHTTPD.IHTTPSession session) {
                        String site = getFirstParamValue(session, "site");
                        if (site != null && site.length() > 0 && !site.contains(".")) {
                            Response response =
                                    newFixedLengthResponse(
                                            NanoHTTPD.Response.Status.REDIRECT,
                                            NanoHTTPD.MIME_HTML,
                                            "Redirect");
                            response.addHeader(HttpFieldsNames.LOCATION, site);
                            return response;
                        }
                        String response = "<html><body></body></html>";
                        return newFixedLengthResponse(response);
                    }
                });
        HttpMessage msg = getHttpMessage(test + "?site=xxx");
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getParam(), equalTo("site"));
        assertThat(alertsRaised.get(0).getEvidence().endsWith("%2eowasp%2eorg"), equalTo(true));
    }

    @ParameterizedTest
    @ValueSource(strings = {HttpFieldsNames.LOCATION, HttpFieldsNames.REFRESH})
    void shouldReportRedirectWithMetaLocationOrRefresh(String type) throws Exception {
        // Given
        String test = "/";

        nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected NanoHTTPD.Response serve(NanoHTTPD.IHTTPSession session) {
                        String site = getFirstParamValue(session, "site");
                        if (site != null && site.length() > 0) {
                            Response response =
                                    newFixedLengthResponse(
                                            NanoHTTPD.Response.Status.OK,
                                            NanoHTTPD.MIME_HTML,
                                            "<html><head><meta http-equiv=\""
                                                    + type
                                                    + "\" content=\""
                                                    + site
                                                    + "\"></head><body><H1>Redirect></H1></body></html>");
                            return response;
                        }
                        String response = "<html><body></body></html>";
                        return newFixedLengthResponse(response);
                    }
                });
        HttpMessage msg = getHttpMessage(test + "?site=xxx");
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getParam(), equalTo("site"));
        assertThat(alertsRaised.get(0).getEvidence().endsWith(".owasp.org"), equalTo(true));
        assertThat(alertsRaised.get(0).getEvidence().startsWith(HttpHeader.HTTP), equalTo(true));
    }

    private static NanoServerHandler createMetaHandler(String test, String type, String content) {
        return new NanoServerHandler(test) {
            @Override
            protected NanoHTTPD.Response serve(NanoHTTPD.IHTTPSession session) {
                String site = getFirstParamValue(session, "site");
                if (site != null && site.length() > 0) {
                    Response response =
                            newFixedLengthResponse(
                                    NanoHTTPD.Response.Status.OK,
                                    NanoHTTPD.MIME_HTML,
                                    META_TEMPLATE
                                            .replace(TYPE_TOKEN, type)
                                            .replace(CONTENT_TOKEN, content + site));
                    return response;
                }
                String response = "<html><body></body></html>";
                return newFixedLengthResponse(response);
            }
        };
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldNotReportRedirectWithMetaLocationWhenConcatenated(boolean param) throws Exception {
        // Given
        String test = "/";
        nano.addHandler(
                param
                        ? createMetaHandler(
                                test, HttpFieldsNames.LOCATION, "https://example.com/?q=")
                        : createMetaHandler(
                                test, HttpFieldsNames.LOCATION, "https://example.com/"));
        HttpMessage msg = getHttpMessage(test + "?site=xxx");
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldNotReportRedirectWithMetaRefreshWhenConcatenated(boolean param) throws Exception {
        // Given
        String test = "/";
        nano.addHandler(
                param
                        ? createMetaHandler(
                                test, HttpFieldsNames.REFRESH, "5;url='https://example.com/?q=")
                        : createMetaHandler(
                                test, HttpFieldsNames.REFRESH, "5;url='https://example.com/"));
        HttpMessage msg = getHttpMessage(test + "?site=xxx");
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    private static NanoServerHandler createJsVariableHandler(
            String test, String jsVar, String content) {
        return new NanoServerHandler(test) {
            @Override
            protected NanoHTTPD.Response serve(NanoHTTPD.IHTTPSession session) {
                String site = getFirstParamValue(session, "site");
                if (site != null && site.length() > 0) {
                    Response response =
                            newFixedLengthResponse(
                                    NanoHTTPD.Response.Status.OK,
                                    NanoHTTPD.MIME_HTML,
                                    JS_VAR_TEMPLATE
                                            .replace(JS_VAR_TOKEN, jsVar)
                                            .replace(CONTENT_TOKEN, content + site));
                    return response;
                }
                String response = "<html><body></body></html>";
                return newFixedLengthResponse(response);
            }
        };
    }

    @ParameterizedTest
    @ValueSource(strings = {"location", "location.href"})
    void shouldReportRedirectWithJsLocationAssignment(String jsVar) throws Exception {
        // Given
        String test = "/";
        nano.addHandler(createJsVariableHandler(test, jsVar, ""));
        HttpMessage msg = getHttpMessage(test + "?site=xxx");
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getParam(), equalTo("site"));
        assertThat(alertsRaised.get(0).getEvidence().endsWith(".owasp.org"), equalTo(true));
        assertThat(alertsRaised.get(0).getEvidence().startsWith(HttpHeader.HTTP), equalTo(true));
    }

    private static Stream<Arguments> createJsVarBooleanPairs() {
        return Stream.of(
                Arguments.of("location", true),
                Arguments.of("location", false),
                Arguments.of("location.href", true),
                Arguments.of("location.href", false));
    }

    @ParameterizedTest
    @MethodSource("createJsVarBooleanPairs")
    void shouldNotReportRedirectWithJsLocationAssignmentWhenConcatenated(
            String jsVar, boolean param) throws Exception {
        // Given
        String test = "/";
        nano.addHandler(
                param
                        ? createJsVariableHandler(test, jsVar, "http://www.example.com/?q=")
                        : createJsVariableHandler(test, jsVar, "http://www.example.com/"));
        HttpMessage msg = getHttpMessage(test + "?site=xxx");
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    private static NanoServerHandler createJsMethodHandler(
            String test, String jsMethod, String content) {
        return new NanoServerHandler(test) {
            @Override
            protected NanoHTTPD.Response serve(NanoHTTPD.IHTTPSession session) {
                String site = getFirstParamValue(session, "site");
                if (site != null && site.length() > 0) {
                    Response response =
                            newFixedLengthResponse(
                                    NanoHTTPD.Response.Status.OK,
                                    NanoHTTPD.MIME_HTML,
                                    JS_METHOD_TEMPLATE
                                            .replace(JS_METHOD_TOKEN, jsMethod)
                                            .replace(CONTENT_TOKEN, content + site));
                    return response;
                }
                String response = "<html><body></body></html>";
                return newFixedLengthResponse(response);
            }
        };
    }

    @ParameterizedTest
    @ValueSource(strings = {"location.reload", "location.replace", "location.assign"})
    void shouldReportRedirectWithJsLocationMethods(String jsMethod) throws Exception {
        // Given
        String test = "/";
        nano.addHandler(createJsMethodHandler(test, jsMethod, ""));
        HttpMessage msg = getHttpMessage(test + "?site=xxx");
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getParam(), equalTo("site"));
        assertThat(alertsRaised.get(0).getEvidence().endsWith(".owasp.org"), equalTo(true));
        assertThat(alertsRaised.get(0).getEvidence().startsWith(HttpHeader.HTTP), equalTo(true));
    }

    private static Stream<Arguments> createJsMethodBooleanPairs() {
        return Stream.of(
                Arguments.of("location.reload", true),
                Arguments.of("location.reload", false),
                Arguments.of("location.replace", true),
                Arguments.of("location.replace", false),
                Arguments.of("location.assign", true),
                Arguments.of("location.assign", false));
    }

    @ParameterizedTest
    @MethodSource("createJsMethodBooleanPairs")
    void shouldNotReportRedirectWithJsLocationMethodsWhenConcatenated(
            String jsMethod, boolean param) throws Exception {
        // Given
        String test = "/";
        nano.addHandler(
                param
                        ? createJsMethodHandler(test, jsMethod, "http://www.example.com/?q=")
                        : createJsMethodHandler(test, jsMethod, "http://www.example.com/"));
        HttpMessage msg = getHttpMessage(test + "?site=xxx");
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @ParameterizedTest
    @ValueSource(strings = {"window.open", "window.navigate"})
    void shouldReportRedirectWithJsWindowMethods(String jsMethod) throws Exception {
        // Given
        String test = "/";
        nano.addHandler(createJsMethodHandler(test, jsMethod, ""));
        HttpMessage msg = getHttpMessage(test + "?site=xxx");
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getParam(), equalTo("site"));
        assertThat(alertsRaised.get(0).getEvidence().endsWith(".owasp.org"), equalTo(true));
        assertThat(alertsRaised.get(0).getEvidence().startsWith(HttpHeader.HTTP), equalTo(true));
    }

    private static Stream<Arguments> createJsWindowBooleanPairs() {
        return Stream.of(
                Arguments.of("window.open", true),
                Arguments.of("window.open", false),
                Arguments.of("window.navigate", true),
                Arguments.of("window.navigate", false));
    }

    @ParameterizedTest
    @MethodSource("createJsWindowBooleanPairs")
    void shouldNotReportRedirectWithJsWindowMethodsWhenConcatenated(String jsMethod, boolean param)
            throws Exception {
        // Given
        String test = "/";
        nano.addHandler(
                param
                        ? createJsMethodHandler(test, jsMethod, "http://www.example.com/?q=")
                        : createJsMethodHandler(test, jsMethod, "http://www.example.com/"));
        HttpMessage msg = getHttpMessage(test + "?site=xxx");
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "0; url='http://www.example.com/'", // Single quoted
                "0; url=\"http://www.example.com/\"", // Double quoted
                "0; url=http://www.example.com/", // No quotes
                "0 ; url=http://www.example.com/", // Spaces around semi-colon
                "0;url=http://www.example.com/", // No spaces no quotes
                "0;url = \"http://www.example.com/\"" // Spaces around equals, double quoted
            })
    void shouldMatchRefreshUrl(String input) {
        // Given / When
        String extracted = ExternalRedirectScanRule.getRefreshUrl(input);
        // Then
        assertThat(extracted, is(equalTo("http://www.example.com/")));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "url='http://www.example.com/'", // Single quotes
                "url=\"http://www.example.com/\"", // Double quotes
                "url=http://www.example.com/", // No spaces
                "url= http://www.example.com/", // Space after equals
                "url =http://www.example.com/", // Space before equals
                "url = \"http://www.example.com/\"" // Spaces around equals, double quoted
            })
    void shouldFindLocationUrl(String input) {
        // Given / When
        String extracted = ExternalRedirectScanRule.getLocationUrl(input);
        // Then
        assertThat(extracted, is(equalTo("http://www.example.com/")));
    }
}
