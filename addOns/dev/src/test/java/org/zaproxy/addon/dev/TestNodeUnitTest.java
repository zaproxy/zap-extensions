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
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.CoreMatchers.sameInstance;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.mock;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;

/**
 * Unit test for the behaviour shared by {@link TestDirectory directories} and {@link TestPage
 * pages}.
 */
class TestNodeUnitTest {

    private TestProxyServer server;

    @BeforeEach
    void setUp() {
        server = mock(TestProxyServer.class);
    }

    @Test
    void shouldHaveNameServerAndParent() {
        // Given
        TestDirectory dir = new TestDirectory(server, "dir");
        TestPage page = new NoStatePage(server, "page");
        // When
        page.setParent(dir);
        // Then
        assertThat(dir.getName(), is(equalTo("dir")));
        assertThat(dir.getServer(), is(sameInstance(server)));
        assertThat(page.getName(), is(equalTo("page")));
        assertThat(page.getServer(), is(sameInstance(server)));
        assertThat(page.getParent(), is(sameInstance(dir)));
    }

    @Test
    void shouldGetHierarchicNameOfDirectory() {
        // Given
        TestDirectory root = new TestDirectory(server, "root");
        TestDirectory sub = new TestDirectory(server, "sub");
        root.addDirectory(sub);
        // When / Then
        assertThat(root.getHierarchicName(), is(equalTo("root")));
        assertThat(sub.getHierarchicName(), is(equalTo("root/sub")));
        assertThat(sub.getParent(), is(sameInstance(root)));
    }

    @Test
    void shouldReturnTheStateRegistered() {
        // Given
        TestDirectory dir = new TestDirectory(server, "dir");
        Set<String> set = new HashSet<>();
        Map<String, String> map = new HashMap<>();
        // When
        Set<String> registeredSet = dir.state(set);
        Map<String, String> registeredMap = dir.state(map);
        // Then
        assertThat(registeredSet, is(sameInstance(set)));
        assertThat(registeredMap, is(sameInstance(map)));
    }

    @Test
    void shouldHaveNoRegisteredStateByDefault() {
        assertThat(new TestDirectory(server, "dir").hasRegisteredState(), is(equalTo(false)));
        assertThat(new NoStatePage(server, "page").hasRegisteredState(), is(equalTo(false)));
    }

    @Test
    void shouldResetRegisteredStateOfDirectory() {
        // Given
        StatefulDir dir = new StatefulDir(server, "dir");
        dir.fill();
        // When
        dir.reset();
        // Then
        assertThat(dir.isEmpty(), is(equalTo(true)));
        assertThat(dir.hasRegisteredState(), is(equalTo(true)));
    }

    @Test
    void shouldResetRegisteredStateOfPage() {
        // Given
        StatefulPage page = new StatefulPage(server, "page");
        page.fill();
        // When
        page.reset();
        // Then
        assertThat(page.isEmpty(), is(equalTo(true)));
        assertThat(page.hasRegisteredState(), is(equalTo(true)));
    }

    @Test
    void shouldResetStateOfSubDirectoriesAndPagesWhenResettingDirectory() {
        // Given
        StatefulDir root = new StatefulDir(server, "root");
        StatefulDir sub = new StatefulDir(server, "sub");
        StatefulPage page = new StatefulPage(server, "page");
        root.addDirectory(sub);
        sub.addPage(page);
        root.fill();
        sub.fill();
        page.fill();

        // When
        root.reset();

        // Then
        assertThat(root.isEmpty(), is(equalTo(true)));
        assertThat(sub.isEmpty(), is(equalTo(true)));
        assertThat(page.isEmpty(), is(equalTo(true)));
    }

    @Test
    void shouldForgetAuthSessionsWhenReset() {
        // Given
        TestAuthDirectory dir = new TestAuthDirectory(server, "auth") {};
        String token = dir.getToken("test@test.com");
        assertThat(dir.getUser(token), is(equalTo("test@test.com")));

        // When
        dir.reset();

        // Then
        assertThat(dir.getUser(token), is(nullValue()));
    }

    @Test
    void shouldLeaveUnregisteredStateWhenReset() {
        // Given
        StatefulDir dir = new StatefulDir(server, "dir");
        dir.unregistered.add("not state");
        // When
        dir.reset();
        // Then
        assertThat(dir.unregistered.size(), is(equalTo(1)));
    }

    @Test
    void shouldCallResetRegisteredWithOnReset() {
        // Given
        AtomicBoolean called = new AtomicBoolean();
        TestPage page =
                new NoStatePage(server, "page") {
                    {
                        onReset(() -> called.set(true));
                    }
                };
        // When
        page.reset();
        // Then
        assertThat(called.get(), is(equalTo(true)));
        assertThat(page.hasRegisteredState(), is(equalTo(true)));
    }

    private static class StatefulDir extends TestDirectory {

        private final Set<String> tokens = state(new HashSet<>());
        private final Map<String, String> sessions = state(new HashMap<>());
        final Set<String> unregistered = new HashSet<>();

        StatefulDir(TestProxyServer server, String name) {
            super(server, name);
        }

        void fill() {
            tokens.add("token");
            sessions.put("key", "value");
        }

        boolean isEmpty() {
            return tokens.isEmpty() && sessions.isEmpty();
        }
    }

    private static class StatefulPage extends NoStatePage {

        private final Set<String> tokens = state(new HashSet<>());
        private final Map<String, String> sessions = state(new HashMap<>());

        StatefulPage(TestProxyServer server, String name) {
            super(server, name);
        }

        void fill() {
            tokens.add("token");
            sessions.put("key", "value");
        }

        boolean isEmpty() {
            return tokens.isEmpty() && sessions.isEmpty();
        }
    }

    private static class NoStatePage extends TestPage {

        NoStatePage(TestProxyServer server, String name) {
            super(server, name);
        }

        @Override
        public void handleMessage(HttpMessageHandlerContext ctx, HttpMessage msg) {
            // Not used.
        }
    }
}
