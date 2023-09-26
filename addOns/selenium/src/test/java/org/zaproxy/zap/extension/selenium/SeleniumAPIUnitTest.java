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
package org.zaproxy.zap.extension.selenium;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.withSettings;

import java.util.Arrays;
import java.util.stream.Stream;
import net.sf.json.JSONObject;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.extension.api.ApiResponse;
import org.zaproxy.zap.extension.api.ApiResponseElement;
import org.zaproxy.zap.extension.selenium.internal.BrowserArgument;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit test for {@link SeleniumAPI}. */
class SeleniumAPIUnitTest extends TestUtils {

    private SeleniumOptions options;
    private SeleniumAPI api;

    @AfterAll
    static void cleanUp() {
        Constant.messages = null;
    }

    @BeforeEach
    void setUp() {
        options = mock(SeleniumOptions.class, withSettings().strictness(Strictness.LENIENT));
        api = new SeleniumAPI(options);
    }

    @Test
    void shouldHavePrefix() throws Exception {
        // Given / When
        String prefix = api.getPrefix();
        // Then
        assertThat(prefix, is(equalTo("selenium")));
    }

    @Test
    void shouldAddApiElements() {
        // Given / When
        api = new SeleniumAPI(options);
        // Then
        assertThat(api.getApiActions(), hasSize(11));
        assertThat(api.getApiViews(), hasSize(10));
        assertThat(api.getApiOthers(), hasSize(0));
    }

    static Stream<String> unknownApiElements() {
        return Stream.of("unknown", "");
    }

    @ParameterizedTest
    @MethodSource("unknownApiElements")
    void shouldThrowApiExceptionForUnknownAction(String name) throws Exception {
        // Given
        JSONObject params = new JSONObject();
        // When
        ApiException exception =
                assertThrows(ApiException.class, () -> api.handleApiAction(name, params));
        // Then
        assertThat(exception.getType(), is(equalTo(ApiException.Type.BAD_ACTION)));
    }

    @ParameterizedTest
    @MethodSource("unknownApiElements")
    void shouldThrowApiExceptionForUnknownView(String name) throws Exception {
        // Given
        JSONObject params = new JSONObject();
        // When
        ApiException exception =
                assertThrows(ApiException.class, () -> api.handleApiView(name, params));
        // Then
        assertThat(exception.getType(), is(equalTo(ApiException.Type.BAD_VIEW)));
    }

    @ParameterizedTest
    @MethodSource("unknownApiElements")
    void shouldThrowApiExceptionForUnknownOther(String name) throws Exception {
        // Given
        HttpMessage message = new HttpMessage();
        JSONObject params = new JSONObject();
        // When
        ApiException exception =
                assertThrows(ApiException.class, () -> api.handleApiOther(message, name, params));
        // Then
        assertThat(exception.getType(), is(equalTo(ApiException.Type.BAD_OTHER)));
    }

    static Stream<String> validBrowserNames() {
        return Stream.of("chrome", "firefox");
    }

    @ParameterizedTest
    @MethodSource("validBrowserNames")
    void shouldReturnOkForAddedBrowserArgument(String browser) throws Exception {
        // Given
        String name = "addBrowserArgument";
        JSONObject params = new JSONObject();
        params.put("browser", browser);
        params.put("argument", "--arg");
        params.put("enabled", "false");
        // When
        ApiResponse response = api.handleApiAction(name, params);
        // Then
        assertThat(response, is(equalTo(ApiResponseElement.OK)));
        verify(options).addBrowserArgument(browser, new BrowserArgument("--arg", false));
    }

    @ParameterizedTest
    @MethodSource("validBrowserNames")
    void shouldDefaultToEnabledForAddedBrowserArgument(String browser) throws Exception {
        // Given
        String name = "addBrowserArgument";
        JSONObject params = new JSONObject();
        params.put("browser", browser);
        params.put("argument", "--arg");
        // When
        ApiResponse response = api.handleApiAction(name, params);
        // Then
        assertThat(response, is(equalTo(ApiResponseElement.OK)));
        verify(options).addBrowserArgument(browser, new BrowserArgument("--arg", true));
    }

    @ParameterizedTest
    @MethodSource("validBrowserNames")
    void shouldReturnOkForRemovedBrowserArgument(String browser) throws Exception {
        // Given
        String name = "removeBrowserArgument";
        JSONObject params = new JSONObject();
        params.put("browser", browser);
        params.put("argument", "--arg");
        given(options.removeBrowserArgument(eq(browser), any())).willReturn(true);
        // When
        ApiResponse response = api.handleApiAction(name, params);
        // Then
        assertThat(response, is(equalTo(ApiResponseElement.OK)));
        verify(options).removeBrowserArgument(browser, "--arg");
    }

    @ParameterizedTest
    @MethodSource("validBrowserNames")
    void shouldThrowApiExceptionForMissingRemovedBrowserArgument(String browser) throws Exception {
        // Given
        String name = "removeBrowserArgument";
        JSONObject params = new JSONObject();
        params.put("browser", browser);
        params.put("argument", "--arg");
        given(options.removeBrowserArgument(eq(browser), any())).willReturn(false);
        // When
        ApiException exception =
                assertThrows(ApiException.class, () -> api.handleApiAction(name, params));
        // Then
        assertThat(exception.getType(), is(equalTo(ApiException.Type.DOES_NOT_EXIST)));
        verify(options).removeBrowserArgument(browser, "--arg");
    }

    @ParameterizedTest
    @MethodSource("validBrowserNames")
    void shouldReturnOkForChangedBrowserArgument(String browser) throws Exception {
        // Given
        String name = "setBrowserArgumentEnabled";
        JSONObject params = new JSONObject();
        params.put("browser", browser);
        params.put("argument", "--arg");
        params.put("enabled", "false");
        given(options.setBrowserArgumentEnabled(eq(browser), any(), anyBoolean())).willReturn(true);
        // When
        ApiResponse response = api.handleApiAction(name, params);
        // Then
        assertThat(response, is(equalTo(ApiResponseElement.OK)));
        verify(options).setBrowserArgumentEnabled(browser, "--arg", false);
    }

    @ParameterizedTest
    @MethodSource("validBrowserNames")
    void shouldThrowApiExceptionForMissingChangedBrowserArgument(String browser) throws Exception {
        // Given
        String name = "setBrowserArgumentEnabled";
        JSONObject params = new JSONObject();
        params.put("browser", browser);
        params.put("argument", "--arg");
        params.put("enabled", "true");
        given(options.setBrowserArgumentEnabled(eq(browser), any(), anyBoolean()))
                .willReturn(false);
        // When
        ApiException exception =
                assertThrows(ApiException.class, () -> api.handleApiAction(name, params));
        // Then
        assertThat(exception.getType(), is(equalTo(ApiException.Type.DOES_NOT_EXIST)));
        verify(options).setBrowserArgumentEnabled(browser, "--arg", true);
    }

    @ParameterizedTest
    @MethodSource("validBrowserNames")
    void shouldGetBrowserArguments(String browser) throws Exception {
        // Given
        String name = "getBrowserArguments";
        JSONObject params = new JSONObject();
        params.put("browser", browser);
        given(options.getBrowserArguments(browser))
                .willReturn(
                        Arrays.asList(
                                new BrowserArgument("--arg", true),
                                new BrowserArgument("--other-arg", false)));
        // When
        ApiResponse response = api.handleApiView(name, params);
        // Then
        assertThat(response.getName(), is(equalTo(name)));
        assertThat(
                response.toJSON().toString(),
                is(
                        equalTo(
                                "{\"getBrowserArguments\":[{\"argument\":\"--arg\",\"enabled\":true},"
                                        + "{\"argument\":\"--other-arg\",\"enabled\":false}]}")));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {"addBrowserArgument", "removeBrowserArgument", "setBrowserArgumentEnabled"})
    void shouldThrowApiExceptionForUnsupportedBrowsersInBrowserArgumentActions(String name)
            throws Exception {
        // Given
        JSONObject params = new JSONObject();
        params.put("browser", "not supported");
        // When
        ApiException exception =
                assertThrows(ApiException.class, () -> api.handleApiAction(name, params));
        // Then
        assertThat(exception.getType(), is(equalTo(ApiException.Type.ILLEGAL_PARAMETER)));
        assertThat(exception.getMessage(), containsString(" (browser)"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"getBrowserArguments"})
    void shouldThrowApiExceptionForUnsupportedBrowsersInBrowserArgumentViews(String name)
            throws Exception {
        // Given
        JSONObject params = new JSONObject();
        params.put("browser", "not supported");
        // When
        ApiException exception =
                assertThrows(ApiException.class, () -> api.handleApiView(name, params));
        // Then
        assertThat(exception.getType(), is(equalTo(ApiException.Type.ILLEGAL_PARAMETER)));
        assertThat(exception.getMessage(), containsString(" (browser)"));
    }
}
