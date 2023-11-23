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
package org.zaproxy.zap.extension.custompayloads;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.emptyString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.api.API;
import org.zaproxy.zap.extension.api.API.RequestType;
import org.zaproxy.zap.extension.api.ApiElement;
import org.zaproxy.zap.extension.api.ApiImplementor;
import org.zaproxy.zap.extension.api.ApiParameter;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit test for {@link CustomPayloadsApi}. */
class CustomPayloadsApiUnitTest extends TestUtils {

    private CustomPayloadsApi api;

    @BeforeEach
    void setUp() {
        mockMessages(new ExtensionCustomPayloads());
        api = new CustomPayloadsApi();
    }

    @Test
    void shouldHavePrefix() throws Exception {
        // Given / When
        String prefix = api.getPrefix();
        // Then
        assertThat(prefix, is(equalTo("custompayloads")));
    }

    @Test
    void shouldHaveDescriptionsForAllApiElements() {
        List<String> missingKeys = new ArrayList<>();
        checkKey(api.getDescriptionKey(), missingKeys);
        checkApiElements(api, api.getApiActions(), API.RequestType.action, missingKeys);
        checkApiElements(api, api.getApiOthers(), API.RequestType.other, missingKeys);
        checkApiElements(api, api.getApiViews(), API.RequestType.view, missingKeys);
        assertThat(missingKeys, is(empty()));
    }

    private static void checkApiElements(
            ApiImplementor api,
            List<? extends ApiElement> elements,
            RequestType type,
            List<String> missingKeys) {
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
