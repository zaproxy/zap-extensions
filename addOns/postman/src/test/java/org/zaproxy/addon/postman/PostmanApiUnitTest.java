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
package org.zaproxy.addon.postman;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.emptyString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.verify;

import java.util.ArrayList;
import java.util.List;
import net.sf.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedConstruction;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.api.ApiElement;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.extension.api.ApiImplementor;
import org.zaproxy.zap.extension.api.ApiParameter;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit test for {@link PostmanApi}. */
class PostmanApiUnitTest extends TestUtils {

    private PostmanApi api;

    @BeforeEach
    void setUp() {
        mockMessages(new ExtensionPostman());
        api = new PostmanApi();
    }

    @Test
    void shouldHavePrefix() {
        // Given / When
        String prefix = api.getPrefix();
        // Then
        assertThat(prefix, is(equalTo("postman")));
    }

    @Test
    void shouldThrowApiExceptionIfMaxMessagesNegativeForUrl() {
        // Given
        JSONObject params = new JSONObject();
        params.put("url", "http://example.com");
        params.put("maxMessages", "-1");
        // When / Then
        ApiException exception =
                assertThrows(ApiException.class, () -> api.handleApiAction("importUrl", params));
        assertThat(exception.getType(), is(equalTo(ApiException.Type.ILLEGAL_PARAMETER)));
        assertThat(exception.toString(), containsString("(illegal_parameter): maxMessages"));
    }

    @Test
    void shouldThrowApiExceptionIfMaxMessagesNegativeForFile() {
        // Given
        JSONObject params = new JSONObject();
        params.put("file", "/tmp/collection.json");
        params.put("maxMessages", "-1");
        // When / Then
        ApiException exception =
                assertThrows(ApiException.class, () -> api.handleApiAction("importFile", params));
        assertThat(exception.getType(), is(equalTo(ApiException.Type.ILLEGAL_PARAMETER)));
        assertThat(exception.toString(), containsString("(illegal_parameter): maxMessages"));
    }

    @Test
    void shouldPassMaxMessagesForUrl() throws Exception {
        // Given
        JSONObject params = new JSONObject();
        params.put("url", "http://example.com/collection.json");
        params.put("maxMessages", "2");
        try (MockedConstruction<PostmanParser> mocked = mockConstruction(PostmanParser.class)) {
            // When
            api.handleApiAction("importUrl", params);
            // Then
            verify(mocked.constructed().get(0))
                    .importFromUrl("http://example.com/collection.json", "", false, 2);
        }
    }

    @Test
    void shouldPassMaxMessagesForFile() throws Exception {
        // Given
        JSONObject params = new JSONObject();
        params.put("file", "/tmp/collection.json");
        params.put("maxMessages", "1");
        try (MockedConstruction<PostmanParser> mocked = mockConstruction(PostmanParser.class)) {
            // When
            api.handleApiAction("importFile", params);
            // Then
            verify(mocked.constructed().get(0))
                    .importFromFile("/tmp/collection.json", "", false, 1);
        }
    }

    @Test
    void shouldHaveDescriptionsForAllApiElements() {
        List<String> missingKeys = new ArrayList<>();
        checkKey(api.getDescriptionKey(), missingKeys);
        checkApiElements(api, api.getApiActions(), missingKeys);
        checkApiElements(api, api.getApiOthers(), missingKeys);
        checkApiElements(api, api.getApiViews(), missingKeys);
        assertThat(missingKeys, is(empty()));
    }

    private static void checkApiElements(
            ApiImplementor api, List<? extends ApiElement> elements, List<String> missingKeys) {
        elements.sort((a, b) -> a.getName().compareTo(b.getName()));
        for (ApiElement element : elements) {
            assertThat(
                    "API element: " + api.getPrefix() + "/" + element.getName(),
                    element.getDescriptionTag(),
                    is(not(emptyString())));
            checkKey(element.getDescriptionTag(), missingKeys);
            element.getParameters().stream()
                    .map(ApiParameter::getDescriptionKey)
                    .forEach(key -> checkKey(key, missingKeys));
        }
    }

    private static void checkKey(String key, List<String> missingKeys) {
        if (!Constant.messages.containsKey(key)) {
            missingKeys.add(key);
        }
    }
}
