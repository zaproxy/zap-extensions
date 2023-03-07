/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.addon.authhelper;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.ArgumentCaptor;
import org.parosproxy.paros.db.RecordContext;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.zaproxy.addon.authhelper.HeaderBasedSessionManagementMethodType.HeaderBasedSessionManagementMethod;
import org.zaproxy.addon.authhelper.HeaderBasedSessionManagementMethodType.HttpHeaderBasedSession;
import org.zaproxy.zap.extension.script.ScriptVars;
import org.zaproxy.zap.network.HttpRequestBody;
import org.zaproxy.zap.network.HttpResponseBody;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.Pair;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

class HeaderBasedSessionManagementMethodTypeUnitTest extends TestUtils {

    private HashMap<String, String> envVars;

    private static final String HEADER_1 = "aaa";
    private static final String VALUE_1 = "bbb";
    private static final String HEADER_2 = "header:with:colons";
    private static final String VALUE_2 = "ccc";
    private static final String HEADER_3 = "ddd";
    private static final String VALUE_3 = "value:with:colon";
    private static final String HEADER_4 = "header-no-value";
    private static final String VALUE_4 = "";
    private static final String HEADER_5 = "h{%json:path.to.data%}-{%env:env-var%}";
    private static final String VALUE_5 = "v{%script:sc_var%}-{%url:test%}";

    @BeforeEach
    void setUp() throws Exception {
        mockMessages(new ExtensionAuthhelper());
        envVars = new HashMap<>();
        HeaderBasedSessionManagementMethod.replaceEnvVarsForTesting(envVars);
        ScriptVars.clearGlobalVars();
    }

    @Test
    void shouldDefaultToNoTokens() throws Exception {
        // Given
        HttpMessage msg =
                new HttpMessage(
                        new HttpRequestHeader(
                                "GET / HTTP/1.1\r\n"
                                        + "Header1: Value1\r\n"
                                        + "Header2: Value2\r\n"
                                        + "Host: example.com\r\n\r\n"),
                        new HttpRequestBody("Request Body"),
                        new HttpResponseHeader("HTTP/1.1 200 OK\r\n"),
                        new HttpResponseBody("Response Body"));
        // When
        Map<String, String> tokens = HeaderBasedSessionManagementMethod.getAllTokens(msg);
        // Then
        assertThat(tokens.size(), is(equalTo(0)));
    }

    @Test
    void shouldExtractHeaderTokens() throws Exception {
        // Given
        HttpMessage msg =
                new HttpMessage(
                        new HttpRequestHeader("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
                        new HttpRequestBody("Request Body"),
                        new HttpResponseHeader(
                                "HTTP/1.1 200 OK\r\n"
                                        + "Header1: Value1\r\n"
                                        + "Header2: Value2\r\n"),
                        new HttpResponseBody("Response Body"));
        // When
        Map<String, String> tokens = HeaderBasedSessionManagementMethod.getAllTokens(msg);
        // Then
        assertThat(tokens.size(), is(equalTo(2)));
        assertThat(tokens.get("header:Header1"), is(equalTo("Value1")));
        assertThat(tokens.get("header:Header2"), is(equalTo("Value2")));
    }

    @Test
    void shouldExtractEnvVarTokens() throws Exception {
        // Given
        HttpMessage msg =
                new HttpMessage(
                        new HttpRequestHeader("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
                        new HttpRequestBody("Request Body"),
                        new HttpResponseHeader("HTTP/1.1 200 OK\r\n"),
                        new HttpResponseBody("Response Body"));
        envVars.put("envvar1", "envvalue1");
        envVars.put("envvar2", "envvalue2");
        // When
        Map<String, String> tokens = HeaderBasedSessionManagementMethod.getAllTokens(msg);
        // Then
        assertThat(tokens.size(), is(equalTo(2)));
        assertThat(tokens.get("env:envvar1"), is(equalTo("envvalue1")));
        assertThat(tokens.get("env:envvar2"), is(equalTo("envvalue2")));
    }

    @Test
    void shouldExtractScriptGlobalTokens() throws Exception {
        // Given
        HttpMessage msg =
                new HttpMessage(
                        new HttpRequestHeader("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
                        new HttpRequestBody("Request Body"),
                        new HttpResponseHeader("HTTP/1.1 200 OK\r\n"),
                        new HttpResponseBody("Response Body"));
        ScriptVars.setGlobalVar("scriptvar1", "scriptvalue1");
        ScriptVars.setGlobalVar("scriptvar2", "scriptvalue2");
        // When
        Map<String, String> tokens = HeaderBasedSessionManagementMethod.getAllTokens(msg);
        // Then
        assertThat(tokens.size(), is(equalTo(2)));
        assertThat(tokens.get("script:scriptvar1"), is(equalTo("scriptvalue1")));
        assertThat(tokens.get("script:scriptvar2"), is(equalTo("scriptvalue2")));
    }

    @Test
    void shouldExtractUrlParams() throws Exception {
        // Given
        HttpMessage msg =
                new HttpMessage(
                        new HttpRequestHeader(
                                "GET https://example.com/?att1=val1&att2=val2 HTTP/1.1\r\nHost: example.com\r\n\r\n"),
                        new HttpRequestBody("Request Body"),
                        new HttpResponseHeader("HTTP/1.1 200 OK\r\n"),
                        new HttpResponseBody("Response Body"));
        // When
        Map<String, String> tokens = HeaderBasedSessionManagementMethod.getAllTokens(msg);
        // Then
        assertThat(tokens.size(), is(equalTo(2)));
        assertThat(tokens.get("url:att1"), is(equalTo("val1")));
        assertThat(tokens.get("url:att2"), is(equalTo("val2")));
    }

    @Test
    void shouldExtractJsonTokens() throws Exception {
        // Given
        HttpMessage msg =
                new HttpMessage(
                        new HttpRequestHeader("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
                        new HttpRequestBody("Request Body"),
                        new HttpResponseHeader(
                                "HTTP/1.1 200 OK\r\n" + "Content-Type: application/json"),
                        new HttpResponseBody(
                                "{'wrapper1': {\n"
                                        + "  'att1': 'val1',\n"
                                        + "  'att2': 'val2',\n"
                                        + "  'wrapper2': {\n"
                                        + "    'att1': 'val3',\n"
                                        + "    'array': [\n"
                                        + "      {'att1': 'val4', 'att2': 'val5'},\n"
                                        + "      {'att3': 'val6', 'att4': 'val7'}\n"
                                        + "    ]\n"
                                        + "  }\n"
                                        + "}}"));
        // When
        Map<String, String> tokens = HeaderBasedSessionManagementMethod.getAllTokens(msg);
        // Then
        assertThat(tokens.size(), is(equalTo(8)));
        assertThat(tokens.get("json:wrapper1.att1"), is(equalTo("val1")));
        assertThat(tokens.get("json:wrapper1.att2"), is(equalTo("val2")));
        assertThat(tokens.get("json:wrapper1.wrapper2.att1"), is(equalTo("val3")));
        assertThat(tokens.get("json:wrapper1.wrapper2.array[0].att1"), is(equalTo("val4")));
        assertThat(tokens.get("json:wrapper1.wrapper2.array[0].att2"), is(equalTo("val5")));
        assertThat(tokens.get("json:wrapper1.wrapper2.array[1].att3"), is(equalTo("val6")));
        assertThat(tokens.get("json:wrapper1.wrapper2.array[1].att4"), is(equalTo("val7")));
        assertThat(tokens.get("header:Content-Type"), is(equalTo("application/json")));
    }

    @Test
    void shouldReplaceSimpleTokens() throws Exception {
        // Given
        String baseString = "Prefix{%token1%}middle{%token2%}Postfix";
        Map<String, String> map = new HashMap<>();
        map.put("token1", "-value1-");
        map.put("token2", "-value2-");
        map.put("token3", "-value3-");
        // When
        String res = HeaderBasedSessionManagementMethod.replaceTokens(baseString, map);
        // Then
        assertThat(res, is(equalTo("Prefix-value1-middle-value2-Postfix")));
    }

    @Test
    void shouldLeaveMissingTokens() throws Exception {
        // Given
        String baseString = "Prefix{%token1%}middle{%token2%}Postfix";
        Map<String, String> map = new HashMap<>();
        map.put("token1", "-value1-");
        map.put("token3", "-value3-");
        // When
        String res = HeaderBasedSessionManagementMethod.replaceTokens(baseString, map);
        // Then
        assertThat(res, is(equalTo("Prefix-value1-middle{%token2%}Postfix")));
    }

    @Test
    void shouldExtractWebSession() throws Exception {
        // Given
        HeaderBasedSessionManagementMethod method = new HeaderBasedSessionManagementMethod();
        HttpMessage msg =
                new HttpMessage(
                        new HttpRequestHeader(
                                "GET https://example.com/?att1=val1&att2=val2 HTTP/1.1\r\n"
                                        + "Header1: Value1\r\n"
                                        + "Header2: Value2\r\n"
                                        + "Host: example.com\r\n\r\n"),
                        new HttpRequestBody("Request Body"),
                        new HttpResponseHeader(
                                "HTTP/1.1 200 OK\r\n"
                                        + "Header3: Value3\r\n"
                                        + "Header4: Value4\r\n"
                                        + "Content-Type: application/json"),
                        new HttpResponseBody(
                                "{'wrapper1': {\n"
                                        + "  'att1': 'val1',\n"
                                        + "  'att2': 'val2',\n"
                                        + "  'wrapper2': {\n"
                                        + "    'att1': 'val3',\n"
                                        + "    'array': [\n"
                                        + "      {'att1': 'val4'},\n"
                                        + "      {'att3': 'val6', 'att4': 'val7'}\n"
                                        + "    ]\n"
                                        + "  }\n"
                                        + "}}"));
        envVars.put("envvar1", "envvalue1");
        envVars.put("envvar2", "envvalue2");
        ScriptVars.setGlobalVar("scriptvar1", "scriptvalue1");
        ScriptVars.setGlobalVar("scriptvar2", "scriptvalue2");
        List<Pair<String, String>> headerConfigs = new ArrayList<>();
        headerConfigs.add(new Pair<>("Header", "{%header:Header3%}"));
        headerConfigs.add(new Pair<>("UrlParam", "xxx-{%url:att2%}"));
        headerConfigs.add(new Pair<>("NoToken", "abc123"));
        headerConfigs.add(new Pair<>("Json", "{%json:wrapper1.wrapper2.array[0].att1%}-yyy"));
        headerConfigs.add(new Pair<>("NoReplacement", "{%header:HeaderX%}"));
        headerConfigs.add(new Pair<>("EnvVar", "11-{%env:envvar2%}-22"));
        headerConfigs.add(new Pair<>("ScriptVar", "{%script:scriptvar1%}"));

        method.setHeaderConfigs(headerConfigs);

        // When
        List<Pair<String, String>> headers = method.extractWebSession(msg).getHeaders();

        // Then
        assertThat(headers.size(), is(equalTo(headerConfigs.size())));
        assertThat(headers.get(0).first, is(equalTo("Header")));
        assertThat(headers.get(0).second, is(equalTo("Value3")));
        assertThat(headers.get(1).first, is(equalTo("UrlParam")));
        assertThat(headers.get(1).second, is(equalTo("xxx-val2")));
        assertThat(headers.get(2).first, is(equalTo("NoToken")));
        assertThat(headers.get(2).second, is(equalTo("abc123")));
        assertThat(headers.get(3).first, is(equalTo("Json")));
        assertThat(headers.get(3).second, is(equalTo("val4-yyy")));
        assertThat(headers.get(4).first, is(equalTo("NoReplacement")));
        assertThat(headers.get(4).second, is(equalTo("{%header:HeaderX%}")));
        assertThat(headers.get(5).first, is(equalTo("EnvVar")));
        assertThat(headers.get(5).second, is(equalTo("11-envvalue2-22")));
        assertThat(headers.get(6).first, is(equalTo("ScriptVar")));
        assertThat(headers.get(6).second, is(equalTo("scriptvalue1")));
    }

    @Test
    void shouldProcessMessageToMatchSession() throws Exception {
        // Given
        HttpMessage msg =
                new HttpMessage(
                        new HttpRequestHeader(
                                "GET / HTTP/1.1\r\n"
                                        + "Header1: Value1\r\n"
                                        + "Header2: Value2\r\n"
                                        + "Host: example.com\r\n\r\n"),
                        new HttpRequestBody("Request Body"),
                        new HttpResponseHeader("HTTP/1.1 200 OK\r\n"),
                        new HttpResponseBody("Response Body"));
        HeaderBasedSessionManagementMethod method = new HeaderBasedSessionManagementMethod();

        List<Pair<String, String>> headers = new ArrayList<>();
        headers.add(new Pair<>("Header1", "Replace1"));
        headers.add(new Pair<>("Header3", "Value3"));
        HttpHeaderBasedSession ws = new HttpHeaderBasedSession(headers);

        // When
        method.processMessageToMatchSession(msg, ws);
        HttpRequestHeader reqHeader = msg.getRequestHeader();

        // Then
        assertThat(reqHeader.getHeaders().size(), is(equalTo(4)));
        assertThat(reqHeader.getHeader("Header1"), is(equalTo("Replace1")));
        assertThat(reqHeader.getHeader("Header2"), is(equalTo("Value2")));
        assertThat(reqHeader.getHeader("Header3"), is(equalTo("Value3")));
        assertThat(reqHeader.getHeader("Host"), is(equalTo("example.com")));
    }

    @ParameterizedTest
    @CsvSource({
        HEADER_1 + "," + VALUE_1,
        HEADER_2 + "," + VALUE_2,
        HEADER_3 + "," + VALUE_3,
        HEADER_4 + "," + VALUE_4,
        HEADER_5 + "," + VALUE_5
    })
    void shouldExportAndImportData(String key, String value) throws Exception {
        // Given
        HeaderBasedSessionManagementMethod method1 = new HeaderBasedSessionManagementMethod();
        HeaderBasedSessionManagementMethod method2 = new HeaderBasedSessionManagementMethod();
        method1.setHeaderConfigs(new ArrayList<>(Arrays.asList(new Pair<>(key, value))));
        ZapXmlConfiguration config = new ZapXmlConfiguration();
        // When
        method1.getType().exportData(config, method1);
        method2.getType().importData(config, method2);
        List<Pair<String, String>> headers = method2.getHeaderConfigs();
        // Then
        assertThat(headers.size(), is(equalTo(1)));
        assertThat(headers.get(0).first, is(equalTo(key)));
        if (value == null) {
            assertThat(headers.get(0).second, is(equalTo("")));
        } else {
            assertThat(headers.get(0).second, is(equalTo(value)));
        }
    }

    @Test
    void shouldExportAndImportDataWithMultipleHeaders() throws Exception {
        // Given
        HeaderBasedSessionManagementMethod method1 = new HeaderBasedSessionManagementMethod();
        HeaderBasedSessionManagementMethod method2 = new HeaderBasedSessionManagementMethod();
        method1.setHeaderConfigs(
                new ArrayList<>(
                        Arrays.asList(
                                new Pair<>(HEADER_1, VALUE_1),
                                new Pair<>(HEADER_2, VALUE_2),
                                new Pair<>(HEADER_3, VALUE_3),
                                new Pair<>(HEADER_4, VALUE_4),
                                new Pair<>(HEADER_5, VALUE_5))));
        ZapXmlConfiguration config = new ZapXmlConfiguration();
        // When
        method1.getType().exportData(config, method1);
        method2.getType().importData(config, method2);
        List<Pair<String, String>> headers = method2.getHeaderConfigs();
        // Then
        assertThat(headers.size(), is(equalTo(5)));
        assertThat(headers.get(0).first, is(equalTo(HEADER_1)));
        assertThat(headers.get(0).second, is(equalTo(VALUE_1)));
        assertThat(headers.get(1).first, is(equalTo(HEADER_2)));
        assertThat(headers.get(1).second, is(equalTo(VALUE_2)));
        assertThat(headers.get(2).first, is(equalTo(HEADER_3)));
        assertThat(headers.get(2).second, is(equalTo(VALUE_3)));
        assertThat(headers.get(3).first, is(equalTo(HEADER_4)));
        assertThat(headers.get(3).second, is(equalTo(VALUE_4)));
        assertThat(headers.get(4).first, is(equalTo(HEADER_5)));
        assertThat(headers.get(4).second, is(equalTo(VALUE_5)));
    }

    @Test
    void shouldPersistAndLoadFromSession() throws Exception {
        // Given
        HeaderBasedSessionManagementMethod method1 = new HeaderBasedSessionManagementMethod();
        HeaderBasedSessionManagementMethod method2 = new HeaderBasedSessionManagementMethod();
        method1.setHeaderConfigs(
                new ArrayList<>(
                        Arrays.asList(
                                new Pair<>(HEADER_1, VALUE_1),
                                new Pair<>(HEADER_2, VALUE_2),
                                new Pair<>(HEADER_3, VALUE_3),
                                new Pair<>(HEADER_4, VALUE_4),
                                new Pair<>(HEADER_5, VALUE_5))));
        Session session = mock(Session.class);
        ArgumentCaptor<String> valueCapture = ArgumentCaptor.forClass(String.class);

        doNothing().when(session).setContextData(anyInt(), anyInt(), valueCapture.capture());
        method1.getType().persistMethodToSession(session, 1, method1);
        when(session.getContextDataString(1, RecordContext.TYPE_SESSION_MANAGEMENT_FIELD_1, ""))
                .thenReturn(valueCapture.getValue());

        // When
        method2 =
                (HeaderBasedSessionManagementMethod)
                        method2.getType().loadMethodFromSession(session, 1);
        List<Pair<String, String>> headers = method2.getHeaderConfigs();
        Map<String, String> map = new HashMap<String, String>(headers.size());
        headers.forEach(p -> map.put(p.first, p.second));

        // Then
        assertThat(headers.size(), is(equalTo(5)));
        assertThat(map.get(HEADER_1), is(equalTo(VALUE_1)));
        assertThat(map.get(HEADER_2), is(equalTo(VALUE_2)));
        assertThat(map.get(HEADER_3), is(equalTo(VALUE_3)));
        assertThat(map.get(HEADER_4), is(equalTo(VALUE_4)));
        assertThat(map.get(HEADER_5), is(equalTo(VALUE_5)));
    }
}
