/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.addon.llm.automation;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zaproxy.addon.llm.ExtensionLlm;
import org.zaproxy.addon.llm.LlmProvider;
import org.zaproxy.addon.llm.automation.LlmConfigJob.Provider;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit tests for {@link LlmProviderTableModel}. */
class LlmProviderTableModelUnitTest extends TestUtils {

    private LlmProviderTableModel model;

    @BeforeEach
    void setUp() {
        mockMessages(new ExtensionLlm());
        model = new LlmProviderTableModel();
    }

    @Test
    void shouldHaveFourColumns() {
        assertThat(model.getColumnCount(), is(4));
        assertThat(model.getColumnName(0), is(equalTo("Name")));
    }

    @Test
    void shouldShowProviderValues() {
        // Given
        Provider provider = provider("a");
        provider.setType(LlmProvider.OLLAMA);
        provider.setEndpoint("http://localhost");
        provider.setModels(List.of("m1", "m2"));

        // When
        model.add(provider);

        // Then
        assertThat(model.getRowCount(), is(1));
        assertThat(model.getValueAt(0, 0), is(equalTo("a")));
        assertThat(model.getValueAt(0, 1), is(equalTo(LlmProvider.OLLAMA.toString())));
        assertThat(model.getValueAt(0, 2), is(equalTo("http://localhost")));
        assertThat(model.getValueAt(0, 3), is(equalTo("m1, m2")));
    }

    @Test
    void shouldShowEmptyValuesForPartialProvider() {
        // When
        model.add(provider("a"));

        // Then
        assertThat(model.getValueAt(0, 1), is(equalTo("")));
        assertThat(model.getValueAt(0, 2), is(nullValue()));
        assertThat(model.getValueAt(0, 3), is(equalTo("")));
    }

    @Test
    void shouldUpdateAndRemove() {
        // Given
        model.add(provider("a"));
        model.add(provider("b"));

        // When
        model.update(0, provider("c"));
        model.remove(1);
        model.remove(5);

        // Then
        assertThat(names(), contains("c"));
    }

    @Test
    void shouldCopyProvidersWhenSet() {
        // Given
        List<Provider> providers = new ArrayList<>(List.of(provider("a")));

        // When
        model.setProviders(providers);
        model.add(provider("b"));

        // Then
        assertThat(providers.size(), is(1));
        assertThat(names(), contains("a", "b"));
    }

    @Test
    void shouldAcceptNullProviders() {
        // When
        model.setProviders(null);

        // Then
        assertThat(model.getRowCount(), is(0));
    }

    @Test
    void shouldDetectNamesUsedByOtherProviders() {
        // Given
        model.add(provider("a"));
        model.add(provider("b"));

        // When / Then
        assertThat(model.isNameUsed("a", -1), is(true));
        assertThat(model.isNameUsed(" a ", 1), is(true));
        assertThat(model.isNameUsed("a", 0), is(false));
        assertThat(model.isNameUsed("c", -1), is(false));
    }

    private List<String> names() {
        return model.getProviders().stream().map(Provider::getName).toList();
    }

    private static Provider provider(String name) {
        Provider provider = new Provider();
        provider.setName(name);
        return provider;
    }
}
