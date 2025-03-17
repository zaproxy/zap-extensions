/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
package org.zaproxy.zap.extension.alertFilters;

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
import org.zaproxy.zap.testutils.TestUtils;

/** Unit test for {@link AlertFilterAPI}. */
class AlertFilterApiUnitTest extends TestUtils {

    private AlertFilterAPI alertFiltersApi;

    @BeforeEach
    void setUp() {
        mockMessages(new ExtensionAlertFilters());

        alertFiltersApi = new AlertFilterAPI();
    }

    @AfterAll
    static void cleanUp() {
        Constant.messages = null;
    }

    @Test
    void shouldHavePrefix() {
        // Given / When
        String prefix = alertFiltersApi.getPrefix();
        // Then
        assertThat(prefix, is(equalTo("alertFilter")));
    }

    @Test
    void shouldAddApiElements() {
        // Given / When
        alertFiltersApi = new AlertFilterAPI();
        // Then
        assertThat(alertFiltersApi.getApiActions(), hasSize(10));
        assertThat(alertFiltersApi.getApiViews(), hasSize(2));
        assertThat(alertFiltersApi.getApiOthers(), hasSize(0));
    }

    @ParameterizedTest
    @EmptySource
    @ValueSource(strings = {"unknown", "something"})
    void shouldThrowApiExceptionForUnknownAction(String name) {
        // Given
        JSONObject params = new JSONObject();
        // When
        ApiException exception =
                assertThrows(
                        ApiException.class, () -> alertFiltersApi.handleApiAction(name, params));
        // Then
        assertThat(exception.getType(), is(equalTo(ApiException.Type.BAD_ACTION)));
    }

    @ParameterizedTest
    @EmptySource
    @ValueSource(strings = {"unknown", "something"})
    void shouldThrowApiExceptionForUnknownOther(String name) {
        // Given
        HttpMessage message = new HttpMessage();
        JSONObject params = new JSONObject();
        // When
        ApiException exception =
                assertThrows(
                        ApiException.class,
                        () -> alertFiltersApi.handleApiOther(message, name, params));
        // Then
        assertThat(exception.getType(), is(equalTo(ApiException.Type.BAD_OTHER)));
    }

    @ParameterizedTest
    @EmptySource
    @ValueSource(strings = {"unknown", "something"})
    void shouldThrowApiExceptionForUnknownView(String name) {
        // Given
        JSONObject params = new JSONObject();
        // When
        ApiException exception =
                assertThrows(ApiException.class, () -> alertFiltersApi.handleApiView(name, params));
        // Then
        assertThat(exception.getType(), is(equalTo(ApiException.Type.BAD_VIEW)));
    }

    @Test
    void shouldHaveDescriptionsForAllApiElements() {
        alertFiltersApi = new AlertFilterAPI();
        List<String> missingKeys = new ArrayList<>();
        List<String> missingDescriptions = new ArrayList<>();
        checkKey(alertFiltersApi.getDescriptionKey(), missingKeys, missingDescriptions);
        checkApiElements(
                alertFiltersApi,
                alertFiltersApi.getApiActions(),
                API.RequestType.action,
                missingKeys,
                missingDescriptions);
        checkApiElements(
                alertFiltersApi,
                alertFiltersApi.getApiOthers(),
                API.RequestType.other,
                missingKeys,
                missingDescriptions);
        checkApiElements(
                alertFiltersApi,
                alertFiltersApi.getApiViews(),
                API.RequestType.view,
                missingKeys,
                missingDescriptions);
        assertThat(missingKeys, is(empty()));
        assertThat(missingDescriptions, is(empty()));
    }

    private static void checkKey(String key, List<String> missingKeys, List<String> missingDescs) {
        if (!Constant.messages.containsKey(key)) {
            missingKeys.add(key);
        } else if (Constant.messages.getString(key).isBlank()) {
            missingDescs.add(key);
        }
    }

    private static void checkApiElements(
            ApiImplementor api,
            List<? extends ApiElement> elements,
            RequestType type,
            List<String> missingKeys,
            List<String> missingDescriptions) {
        elements.sort((a, b) -> a.getName().compareTo(b.getName()));
        for (ApiElement element : elements) {
            assertThat(
                    "API " + type + " element: " + api.getPrefix() + "/" + element.getName(),
                    element.getDescriptionTag(),
                    is(not(emptyString())));
            checkKey(element.getDescriptionTag(), missingKeys, missingDescriptions);
            element.getParameters().stream()
                    .map(ApiParameter::getDescriptionKey)
                    .forEach(key -> checkKey(key, missingKeys, missingDescriptions));
        }
    }
}
