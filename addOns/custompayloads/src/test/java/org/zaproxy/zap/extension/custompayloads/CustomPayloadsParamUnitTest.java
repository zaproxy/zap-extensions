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
package org.zaproxy.zap.extension.custompayloads;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/** Unit test for {@link CustomPayloadsParam}. */
class CustomPayloadsParamUnitTest {

    private static CustomPayloadsParam param;
    private ZapXmlConfiguration configuration;

    private static CustomPayload testPayload = new CustomPayload(true, "foo", "bar");

    @BeforeEach
    void setUp() {
        param = new CustomPayloadsParam();
        configuration = new ZapXmlConfiguration();
    }

    @Test
    void shouldHaveConfigVersionKey() {
        // Given / When / Then
        assertThat(param.getConfigVersionKey(), is(equalTo("custompayloads[@version]")));
    }

    @ParameterizedTest
    @ValueSource(strings = {"true", "false"})
    void shouldLoadConfirmRemoveFromConfig(boolean state) {
        // Given
        configuration.setProperty(CustomPayloadsParam.CONFIRM_REMOVE_PAYLOAD_KEY, state);
        // When
        param.load(configuration);
        // Then
        assertThat(param.isConfirmRemoveToken(), is(equalTo(state)));
    }

    @Test
    void shouldDefaultConfirmRemoveTrue() {
        // Given / When
        param.load(configuration);
        // Then
        assertThat(param.isConfirmRemoveToken(), is(equalTo(true)));
    }

    @Test
    void shouldNotHaveNextPayloadIdOnUpdateFromUnversioned() {
        // Given
        String configKey = "custompayloads.nextPayloadId";
        configuration.setProperty(configKey, 72);
        // When
        param.load(configuration);
        // Then
        assertThat(
                (int) configuration.getProperty("custompayloads[@version]"),
                is(greaterThanOrEqualTo(1)));
        assertThat(configuration.getProperty(configKey), is(nullValue()));
    }

    @Test
    void shouldNotLoadPayloadWithNamelessCategory() {
        // Given
        configuration = createUnversionedConfig();
        configuration.clearProperty("custompayloads.categories.category[@name]");
        // When
        param.load(configuration);
        // Then
        assertThat(param.getCategoriesNames(), is(empty()));
        assertThat(param.getPayloads(), is(empty()));
    }

    @Test
    void shouldRemoveIdsFromCustomPayloadsOnUpdate() {
        // Given
        String configKey = "custompayloads.categories.category(0).payloads.payload(0).";
        configuration = createUnversionedConfig();
        // When
        param.load(configuration);
        // Then
        assertThat(
                (int) configuration.getProperty("custompayloads[@version]"),
                is(greaterThanOrEqualTo(1)));
        assertThat(configuration.getProperty(configKey + "id"), is(nullValue()));
        assertThat(param.getCategoriesNames(), hasItem("foo"));
        assertThat(param.getPayloads().size(), is(equalTo(1)));
        CustomPayload payload = param.getPayloads().get(0);
        assertThat(payload.getCategory(), is(equalTo(testPayload.getCategory())));
        assertThat(payload.getPayload(), is(equalTo(testPayload.getPayload())));
    }

    private static ZapXmlConfiguration createUnversionedConfig() {
        ZapXmlConfiguration testConfig = new ZapXmlConfiguration();

        Map<String, PayloadCategory> payloadCategories = new HashMap<>();
        payloadCategories.put(
                testPayload.getCategory(),
                new PayloadCategory(testPayload.getCategory(), List.of(), List.of(testPayload)));
        int catIdx = 0;
        for (PayloadCategory category : payloadCategories.values()) {
            String catElementBaseKey = CustomPayloadsParam.ALL_CATEGORIES_KEY + "(" + catIdx + ")";
            List<CustomPayload> payloads = category.getPayloads();
            testConfig.setProperty(
                    catElementBaseKey + CustomPayloadsParam.CATEGORY_NAME_KEY, category.getName());
            for (int i = 0, size = payloads.size(); i < size; ++i) {
                String elementBaseKey =
                        catElementBaseKey
                                + ".payloads."
                                + CustomPayloadsParam.PAYLOAD_KEY
                                + "("
                                + i
                                + ").";
                CustomPayload payload = payloads.get(i);
                testConfig.setProperty(elementBaseKey + "id", i);
                testConfig.setProperty(
                        elementBaseKey + CustomPayloadsParam.PAYLOAD_ENABLED_KEY,
                        Boolean.valueOf(payload.isEnabled()));
                testConfig.setProperty(
                        elementBaseKey + CustomPayloadsParam.PAYLOAD_KEY, payload.getPayload());
            }
            catIdx++;
        }
        return testConfig;
    }
}
