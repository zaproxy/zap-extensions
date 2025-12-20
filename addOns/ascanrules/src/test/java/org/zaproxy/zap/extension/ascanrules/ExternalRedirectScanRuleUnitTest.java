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
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

import fi.iki.elonen.NanoHTTPD;
import fi.iki.elonen.NanoHTTPD.Response;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.addon.commonlib.http.HttpFieldsNames;
import org.zaproxy.zap.testutils.NanoServerHandler;

/** Unit test for {@link ExternalRedirectScanRule}. */
class ExternalRedirectScanRuleUnitTest extends ActiveScannerTest<ExternalRedirectScanRule> {

    private static final String ALLOWED_DESTINATION = "https://good.expected.com";

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
        ALLOW_LIST,
        CONCAT_PARAM,
        CONCAT_PATH;
    }

    private static NanoServerHandler createHttpRedirectHandler(String path, String header) {
        return createHttpRedirectHandler(path, header, PayloadHandling.NEITHER);
    }

    private static NanoServerHandler createHttpRedirectHandler(
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
                    case ALLOW_LIST, NEITHER:
                    default:
                        // Nothing to do
                }

                Response response = newFixedLengthResponse("<html><body></body></html>");

                Response redirectResponse =
                        newFixedLengthResponse(
                                NanoHTTPD.Response.Status.REDIRECT,
                                NanoHTTPD.MIME_HTML,
                                "Redirect");
                redirectResponse.addHeader(header, site);

                if (PayloadHandling.ALLOW_LIST.equals(payloadHandling)) {
                    if (site.contains(ALLOWED_DESTINATION)) {
                        return redirectResponse;
                    }
                    return response;
                }
                if (site != null && !site.isEmpty()) {
                    return redirectResponse;
                }
                return response;
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
        assertThat(tags.size(), is(equalTo(13)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A03_INJECTION.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A01_INJECTION.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.WSTG_V42_CLNT_04_OPEN_REDIR.getTag()),
                is(equalTo(true)));
        assertThat(tags.containsKey(CommonAlertTag.HIPAA.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.API.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.DEV_CICD.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.DEV_STD.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.DEV_FULL.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.QA_CICD.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.QA_STD.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.QA_FULL.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.SEQUENCE.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.PENTEST.getTag()), is(equalTo(true)));
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
    @ValueSource(strings = {HttpFieldsNames.LOCATION, HttpFieldsNames.REFRESH})
    void shouldReportRedirectWithLocationOrRefreshHeaderSimpleAllowlist(String header)
            throws Exception {
        // Given
        String test = "/";

        nano.addHandler(createHttpRedirectHandler(test, header, PayloadHandling.ALLOW_LIST));
        HttpMessage msg = getHttpMessage(test + "?site=" + ALLOWED_DESTINATION);
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getParam(), equalTo("site"));
        assertThat(
                alertsRaised.get(0).getAttack().contains(".owasp.org/?" + ALLOWED_DESTINATION),
                equalTo(true));
        assertThat(alertsRaised.get(0).getEvidence().contains(".owasp.org"), equalTo(true));
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
                        if (site != null && !site.isEmpty() && !site.contains(".")) {
                            Response response =
                                    newFixedLengthResponse(
                                            NanoHTTPD.Response.Status.REDIRECT,
                                            NanoHTTPD.MIME_HTML,
                                            "Redirect");
                            response.addHeader(HttpFieldsNames.LOCATION, site);
                            return response;
                        }
                        return newFixedLengthResponse("<html><body></body></html>");
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
                        if (site != null && !site.isEmpty()) {
                            return newFixedLengthResponse(
                                    NanoHTTPD.Response.Status.OK,
                                    NanoHTTPD.MIME_HTML,
                                    "<html><head><meta http-equiv=\""
                                            + type
                                            + "\" content=\""
                                            + site
                                            + "\"></head><body><H1>Redirect></H1></body></html>");
                        }
                        return newFixedLengthResponse("<html><body></body></html>");
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
                if (site != null && !site.isEmpty()) {
                    return newFixedLengthResponse(
                            NanoHTTPD.Response.Status.OK,
                            NanoHTTPD.MIME_HTML,
                            META_TEMPLATE
                                    .replace(TYPE_TOKEN, type)
                                    .replace(CONTENT_TOKEN, content + site));
                }
                return newFixedLengthResponse("<html><body></body></html>");
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
                if (site != null && !site.isEmpty()) {
                    return newFixedLengthResponse(
                            NanoHTTPD.Response.Status.OK,
                            NanoHTTPD.MIME_HTML,
                            JS_VAR_TEMPLATE
                                    .replace(JS_VAR_TOKEN, jsVar)
                                    .replace(CONTENT_TOKEN, content + site));
                }
                return newFixedLengthResponse("<html><body></body></html>");
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
                if (site != null && !site.isEmpty()) {
                    return newFixedLengthResponse(
                            NanoHTTPD.Response.Status.OK,
                            NanoHTTPD.MIME_HTML,
                            JS_METHOD_TEMPLATE
                                    .replace(JS_METHOD_TOKEN, jsMethod)
                                    .replace(CONTENT_TOKEN, content + site));
                }
                return newFixedLengthResponse("<html><body></body></html>");
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

    @Test
    void shouldNotReportRedirectIfInsideJsComment() throws Exception {
        // Given
        String test = "/";
        String body =
                """
                <!DOCTYPE html>
                <html>
                <head>
                <title>Redirect commented out</title>
                </head>
                <body>

                <script>function myRedirectFunction()
                {/*
                window.location.replace('%s');
                */}
                //myRedirectFunction();
                </script>
                """
                        .formatted(CONTENT_TOKEN);
        nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected NanoHTTPD.Response serve(NanoHTTPD.IHTTPSession session) {
                        String site = getFirstParamValue(session, "site");
                        if (site != null && !site.isEmpty()) {
                            String withPayload = body.replace(CONTENT_TOKEN, site);
                            return newFixedLengthResponse(
                                    NanoHTTPD.Response.Status.OK, NanoHTTPD.MIME_HTML, withPayload);
                        }
                        return newFixedLengthResponse("<html><body></body></html>");
                    }
                });
        HttpMessage msg = getHttpMessage(test + "?site=xxx");
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, is(empty()));
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
    @ValueSource(
            strings = {
                "window.open",
                "window.navigate",
                "let r = /http:\\/\\/[a-z]+/g; window.navigate"
            })
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

    /** Unit tests for {@link ExternalRedirectScanRule#extractJsComments(String)}. */
    @Nested
    class ExtractJsCommentsUnitTest {

        private static Stream<Arguments> commentProvider() {
            return Stream.of(
                    Arguments.of("Empty line comment", "//", Set.of("//")),
                    Arguments.of("Empty block comment", "/**/", Set.of("/**/")),
                    Arguments.of("Block comment", "/*  comment \n*/", Set.of("/*  comment \n*/")),
                    Arguments.of(
                            "Line comment with CRLF",
                            "console.log('x'); // comment\r\nconsole.log('y');",
                            Set.of("// comment")),
                    Arguments.of(
                            "Block comment containing line terminator + line comment",
                            "/* block start\n// inside block */ console.log('x');",
                            Set.of("/* block start\n// inside block */")),
                    Arguments.of(
                            "Escaped quote before comment",
                            "console.log('it\\'s fine'); // real comment",
                            Set.of("// real comment")),
                    Arguments.of(
                            "Escaped backslash before comment",
                            "console.log('c:\\\\'); // comment",
                            Set.of("// comment")),
                    Arguments.of("Single line", "// comment ", Set.of("// comment ")),
                    Arguments.of(
                            "Block inside Single line",
                            "// /* comment; */",
                            Set.of("// /* comment; */")),
                    Arguments.of(
                            "Single line inside Block comment",
                            "/*  comment \n // example */",
                            Set.of("/*  comment \n // example */")),
                    Arguments.of(
                            "Inline block",
                            "console.log(\"example\"); /* console.log('comment'); */",
                            Set.of("/* console.log('comment'); */")),
                    Arguments.of(
                            "Inline single line",
                            "console.log(\"example\"); // console.log('comment'));",
                            Set.of("// console.log('comment'));")),
                    Arguments.of(
                            "Inline single line (w/ unicode escape)",
                            "console.log(\"🔥 example\"); // console.log('\u1F525 example');",
                            Set.of("// console.log('\u1F525 example');")),
                    Arguments.of(
                            "Template literal with embedded expression",
                            "console.log(`value ${1 + 1}`); // comment;",
                            Set.of("// comment;")),
                    Arguments.of(
                            "Template expression with block comment",
                            "console.log(`value ${ /* block comment */ 42 }`);",
                            Set.of("/* block comment */")),
                    Arguments.of(
                            "Multiline nested template expression",
                            "console.log(`line1 ${ `inner ${42} // not comment` }`); // real comment",
                            Set.of("// real comment")),
                    Arguments.of(
                            "Nested template with string containing comment-like text",
                            "console.log(`outer ${ 'string // not comment' }`); // real comment",
                            Set.of("// real comment")),
                    Arguments.of(
                            "Regex literal followed by comment",
                            "var re = /abc/; // trailing comment",
                            Set.of("// trailing comment")),
                    Arguments.of(
                            "Regex literal containing /* ... */ in class",
                            "var re = /a\\/\\*b/; // trailing comment",
                            Set.of("// trailing comment")),
                    Arguments.of(
                            "Regex-like in comment",
                            "/* /http:\\/\\/evil.com/ */",
                            Set.of("/* /http:\\/\\/evil.com/ */")));
        }

        @ParameterizedTest(name = "{0}")
        @MethodSource("commentProvider")
        void shouldFindExpectedComments(String name, String input, Set<String> expectedComments) {
            // Given /  When
            Set<String> actualComments = ExternalRedirectScanRule.extractJsComments(input);
            // Then
            assertThat(
                    String.format(
                            "Test '%s' failed. Expected %s but got %s",
                            name, expectedComments, actualComments),
                    actualComments,
                    is(expectedComments));
        }

        private static Stream<Arguments> sequentialCommentsProvider() {
            return Stream.of(
                    Arguments.of(
                            "Single line comment sequence",
                            "// first\n//second\nconsole.log('x');",
                            Set.of("// first", "//second")),
                    Arguments.of(
                            "Single line and block comment sequence",
                            "// first\n/*second*/\nconsole.log('x');",
                            Set.of("// first", "/*second*/")),
                    Arguments.of(
                            "Template expression with inner comment",
                            "console.log(`outer ${ /* inner comment */ 42 }`); // trailing comment",
                            Set.of("/* inner comment */", "// trailing comment")),
                    Arguments.of(
                            "Block comment sequence",
                            "/* first*/\n/*second*/\nconsole.log('x');",
                            Set.of("/* first*/", "/*second*/")));
        }

        @ParameterizedTest(name = "{0}")
        @MethodSource("sequentialCommentsProvider")
        void shouldIdentifyMultipleComments(
                String name, String input, Set<String> expectedComments) {
            // Given / When
            Set<String> actualComments = ExternalRedirectScanRule.extractJsComments(input);
            // Then
            assertThat(
                    "Unexpected comment set for test: " + name,
                    actualComments,
                    equalTo(expectedComments));
        }

        private static Stream<Arguments> nonCommentStringsProvider() {
            return Stream.of(
                    Arguments.of("String containing //", "console.log('not // a comment');"),
                    Arguments.of(
                            "String containing /* */",
                            "console.log('not /* a comment */ either');"),
                    Arguments.of(
                            "Unterminated string before comment",
                            "console.log('unterminated // not a comment"),
                    Arguments.of("regex literal", "let r = /http:\\/\\/example.com/;"),
                    Arguments.of(
                            "regex with comment-like content", "let r = /\\/\\* comment *\\/g;"),
                    // Unterminated template literal results in JS error
                    Arguments.of(
                            "Unterminated template literal",
                            "console.log(`unterminated template ${1+1} // comment not terminated"),
                    Arguments.of(
                            "Inline incomplete block",
                            "console.log(\"example\"); /* console.log('comment');"));
        }

        @ParameterizedTest(name = "{0}")
        @MethodSource("nonCommentStringsProvider")
        void shouldNotFindAComment(String name, String input) {
            // Given / When
            Set<String> comments = ExternalRedirectScanRule.extractJsComments(input);
            // Then
            assertThat(comments, is(empty()));
        }
    }
}
