/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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
package org.zaproxy.addon.pscan;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.emptyString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.ArrayList;
import java.util.List;
import net.sf.json.JSONObject;
import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.api.API;
import org.zaproxy.zap.extension.api.API.RequestType;
import org.zaproxy.zap.extension.api.ApiElement;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.extension.api.ApiImplementor;
import org.zaproxy.zap.extension.api.ApiParameter;
import org.zaproxy.zap.extension.pscan.ExtensionPassiveScan;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit test for {@link PassiveScanApi}. */
class PassiveScanApiUnitTest extends TestUtils {

    private PassiveScanApi pscanApi;
    private ExtensionPassiveScan extension;

    @BeforeEach
    void setUp() {
        mockMessages(new ExtensionPassiveScan2());
        pscanApi = new PassiveScanApi(extension);
    }

    @AfterAll
    static void cleanUp() {
        Constant.messages = null;
    }

    @Test
    void shouldHavePrefix() throws Exception {
        // Given / When
        String prefix = pscanApi.getPrefix();
        // Then
        assertThat(prefix, is(equalTo("pscan")));
    }

    @Test
    void shouldAddApiElements() {
        // Given / When
        pscanApi = new PassiveScanApi(extension);
        // Then
        assertThat(pscanApi.getApiActions(), hasSize(11));
        assertThat(pscanApi.getApiViews(), hasSize(6));
        assertThat(pscanApi.getApiOthers(), hasSize(0));
    }

    @ParameterizedTest
    @EmptySource
    @ValueSource(strings = {"unknown", "something"})
    void shouldThrowApiExceptionForUnknownShortcut(String path) throws Exception {
        // Given
        HttpMessage message = new HttpMessage(new URI("http://zap/" + path, true));
        // When
        ApiException exception =
                assertThrows(ApiException.class, () -> pscanApi.handleShortcut(message));
        // Then
        assertThat(exception.getType(), is(equalTo(ApiException.Type.URL_NOT_FOUND)));
    }

    @ParameterizedTest
    @EmptySource
    @ValueSource(strings = {"unknown", "something"})
    void shouldThrowApiExceptionForUnknownOther(String name) throws Exception {
        // Given
        HttpMessage message = new HttpMessage();
        JSONObject params = new JSONObject();
        // When
        ApiException exception =
                assertThrows(
                        ApiException.class, () -> pscanApi.handleApiOther(message, name, params));
        // Then
        assertThat(exception.getType(), is(equalTo(ApiException.Type.BAD_OTHER)));
    }

    @ParameterizedTest
    @EmptySource
    @ValueSource(strings = {"unknown", "something"})
    void shouldThrowApiExceptionForUnknownAction(String name) throws Exception {
        // Given
        JSONObject params = new JSONObject();
        // When
        ApiException exception =
                assertThrows(ApiException.class, () -> pscanApi.handleApiAction(name, params));
        // Then
        assertThat(exception.getType(), is(equalTo(ApiException.Type.BAD_ACTION)));
    }

    @ParameterizedTest
    @EmptySource
    @ValueSource(strings = {"unknown", "something"})
    void shouldThrowApiExceptionForUnknownView(String name) throws Exception {
        // Given
        JSONObject params = new JSONObject();
        // When
        ApiException exception =
                assertThrows(ApiException.class, () -> pscanApi.handleApiView(name, params));
        // Then
        assertThat(exception.getType(), is(equalTo(ApiException.Type.BAD_VIEW)));
    }

    @Test
    void shouldHaveDescriptionsForAllApiElements() {
        pscanApi = new PassiveScanApi(extension);
        List<String> issues = new ArrayList<>();
        checkKey(pscanApi.getDescriptionKey(), issues);
        checkApiElements(pscanApi, pscanApi.getApiActions(), API.RequestType.action, issues);
        checkApiElements(pscanApi, pscanApi.getApiOthers(), API.RequestType.other, issues);
        checkApiElements(pscanApi, pscanApi.getApiViews(), API.RequestType.view, issues);
        assertThat(issues, is(empty()));
    }

    private static void checkApiElements(
            ApiImplementor api,
            List<? extends ApiElement> elements,
            RequestType type,
            List<String> issues) {
        elements.sort((a, b) -> a.getName().compareTo(b.getName()));
        for (ApiElement element : elements) {
            assertThat(
                    "API element: " + api.getPrefix() + "/" + element.getName(),
                    element.getDescriptionTag(),
                    is(not(emptyString())));
            checkKey(element.getDescriptionTag(), issues);

            element.getParameters().stream()
                    .map(ApiParameter::getDescriptionKey)
                    .forEach(key -> checkKey(key, issues));
        }
    }

    private static void checkKey(String key, List<String> issues) {
        if (!Constant.messages.containsKey(key)) {
            issues.add("Missing key: " + key);
            return;
        }

        var message = Constant.messages.getString(key);
        if (message.isBlank()) {
            issues.add("Key with no message: " + key);
            return;
        }
    }
}
