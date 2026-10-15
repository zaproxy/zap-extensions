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
package org.zaproxy.addon.dev;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.CoreMatchers.sameInstance;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zaproxy.addon.network.ExtensionNetwork;

/** Unit test for plugging directories into the {@link TestProxyServer}. */
class TestProxyServerPluginUnitTest {

    private TestProxyServer server;

    @BeforeEach
    void setUp() {
        server = new TestProxyServer(mock(ExtensionDev.class), mock(ExtensionNetwork.class));
    }

    @Test
    void shouldAddDirectoryToRoot() {
        // Given
        TestDirectory dir = new TestDirectory(server, "plugged");
        // When
        server.addDirectory("", dir);
        // Then
        assertThat(dir.getHierarchicName(), is(equalTo("/plugged")));
    }

    @Test
    void shouldAddDirectoryToExistingParent() {
        // Given
        TestDirectory dir = new TestDirectory(server, "plugged");
        // When
        server.addDirectory("auth", dir);
        // Then
        assertThat(dir.getHierarchicName(), is(equalTo("/auth/plugged")));
    }

    @Test
    void shouldCreateMissingParentDirectories() {
        // Given
        TestDirectory dir = new TestDirectory(server, "mock");
        // When
        server.addDirectory("/llm/nested/", dir);
        // Then
        assertThat(dir.getHierarchicName(), is(equalTo("/llm/nested/mock")));
    }

    @Test
    void shouldShareCreatedParentsBetweenPlugins() {
        // Given
        TestDirectory dir1 = new TestDirectory(server, "one");
        TestDirectory dir2 = new TestDirectory(server, "two");
        // When
        server.addDirectory("shared", dir1);
        server.addDirectory("shared", dir2);
        // Then
        assertThat(dir1.getParent(), is(sameInstance(dir2.getParent())));
    }

    @Test
    void shouldNotAddDirectoryWithExistingName() {
        // Given
        server.addDirectory("", new TestDirectory(server, "plugged"));
        // When / Then
        assertThrows(
                IllegalArgumentException.class,
                () -> server.addDirectory("", new TestDirectory(server, "plugged")));
    }

    @Test
    void shouldRemoveDirectory() {
        // Given
        TestDirectory dir = new TestDirectory(server, "mock");
        server.addDirectory("llm", dir);
        // When
        boolean removed = server.removeDirectory("llm/mock");
        // Then
        assertThat(removed, is(equalTo(true)));
        assertThat(dir.getParent(), is(nullValue()));
    }

    @Test
    void shouldAllowDirectoryToBeAddedAgainAfterRemoval() {
        // Given
        server.addDirectory("llm", new TestDirectory(server, "mock"));
        server.removeDirectory("llm/mock");
        TestDirectory dir = new TestDirectory(server, "mock");
        // When
        server.addDirectory("llm", dir);
        // Then
        assertThat(dir.getParent(), is(notNullValue()));
    }

    @Test
    void shouldNotRemoveUnknownDirectory() {
        // Given / When / Then
        assertThat(server.removeDirectory("unknown/dir"), is(equalTo(false)));
        assertThat(server.removeDirectory(""), is(equalTo(false)));
    }

    @Test
    void shouldResetPluggedDirectories() {
        // Given
        AtomicBoolean reset = new AtomicBoolean();
        TestDirectory dir =
                new TestDirectory(server, "plugged") {
                    {
                        onReset(() -> reset.set(true));
                    }
                };
        server.addDirectory("llm", dir);
        // When
        server.reset();
        // Then
        assertThat(reset.get(), is(equalTo(true)));
    }
}
