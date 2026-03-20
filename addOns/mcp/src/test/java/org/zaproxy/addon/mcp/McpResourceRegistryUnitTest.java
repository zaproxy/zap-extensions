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
package org.zaproxy.addon.mcp;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Unit tests for {@link McpResourceRegistry}. */
class McpResourceRegistryUnitTest {

    private McpResourceRegistry registry;

    @BeforeEach
    void setUp() {
        registry = new McpResourceRegistry();
    }

    @Test
    void shouldRejectNullResource() {
        IllegalArgumentException e =
                assertThrows(IllegalArgumentException.class, () -> registry.registerResource(null));

        assertThat(e.getMessage(), is(equalTo("Resource must not be null")));
    }

    @Test
    void shouldRejectResourceWithNullUri() {
        McpResource resource = resourceWithUri(null);

        IllegalArgumentException e =
                assertThrows(
                        IllegalArgumentException.class, () -> registry.registerResource(resource));

        assertThat(e.getMessage(), is(equalTo("Resource URI must not be null or blank")));
    }

    @Test
    void shouldRejectResourceWithBlankUri() {
        McpResource resource = resourceWithUri("   ");

        IllegalArgumentException e =
                assertThrows(
                        IllegalArgumentException.class, () -> registry.registerResource(resource));

        assertThat(e.getMessage(), is(equalTo("Resource URI must not be null or blank")));
    }

    @Test
    void shouldRegisterAndGetResource() {
        McpResource resource = resourceWithUri("zap://test");
        registry.registerResource(resource);

        assertThat(registry.getResource("zap://test"), is(equalTo(resource)));
    }

    @Test
    void shouldReplaceExistingResourceWithSameUri() {
        McpResource resource1 = resourceWithUri("zap://test");
        McpResource resource2 = resourceWithUri("zap://test");
        registry.registerResource(resource1);
        registry.registerResource(resource2);

        assertThat(registry.getResource("zap://test"), is(equalTo(resource2)));
    }

    @Test
    void shouldReturnNullForUnregisteredResource() {
        assertThat(registry.getResource("zap://unknown"), is(nullValue()));
    }

    @Test
    void shouldResolveResourceByPrefixMatch() {
        McpResource prefixResource = resourceWithUri("zap://history/");
        registry.registerResource(prefixResource);

        assertThat(registry.getResource("zap://history/123"), is(equalTo(prefixResource)));
        assertThat(registry.getResource("zap://history/1"), is(equalTo(prefixResource)));
    }

    @Test
    void shouldPreferLongestPrefixMatch() {
        McpResource shortPrefix = resourceWithUri("zap://history/");
        McpResource longPrefix = resourceWithUri("zap://history/entry/");
        registry.registerResource(shortPrefix);
        registry.registerResource(longPrefix);

        assertThat(registry.getResource("zap://history/123"), is(equalTo(shortPrefix)));
        assertThat(registry.getResource("zap://history/entry/123"), is(equalTo(longPrefix)));
    }

    @Test
    void shouldPreferExactMatchOverPrefixMatch() {
        McpResource exactResource = resourceWithUri("zap://history");
        McpResource prefixResource = resourceWithUri("zap://history/");
        registry.registerResource(exactResource);
        registry.registerResource(prefixResource);

        assertThat(registry.getResource("zap://history"), is(equalTo(exactResource)));
        assertThat(registry.getResource("zap://history/123"), is(equalTo(prefixResource)));
    }

    @Test
    void shouldUnregisterResource() {
        McpResource resource = resourceWithUri("zap://test");
        registry.registerResource(resource);
        registry.unregisterResource("zap://test");

        assertThat(registry.getResource("zap://test"), is(nullValue()));
    }

    @Test
    void shouldReturnAllRegisteredResources() {
        McpResource resource1 = resourceWithUri("zap://a");
        McpResource resource2 = resourceWithUri("zap://b");
        registry.registerResource(resource1);
        registry.registerResource(resource2);

        assertThat(registry.getResources(), hasSize(2));
        assertThat(registry.getResources(), containsInAnyOrder(resource1, resource2));
    }

    @Test
    void shouldReturnEmptyListWhenNoResourcesRegistered() {
        assertThat(registry.getResources(), is(empty()));
    }

    private static McpResource resourceWithUri(String uri) {
        return new McpResource() {
            @Override
            public String getUri() {
                return uri;
            }

            @Override
            public String getName() {
                return "test";
            }

            @Override
            public String getDescription() {
                return "Test resource";
            }

            @Override
            public String getMimeType() {
                return "application/json";
            }

            @Override
            public String readContent() {
                return "{}";
            }
        };
    }
}
