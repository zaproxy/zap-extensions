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
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.mock;

import org.junit.jupiter.api.Test;

/** Unit test for {@link TestAuthDirectory}. */
class TestAuthDirectoryUnitTest {

    private final TestAuthDirectory dir =
            new TestAuthDirectory(mock(TestProxyServer.class), "dir") {};

    @Test
    void shouldReturnNoUserForNullToken() {
        assertThat(dir.getUser(null), is(nullValue()));
    }

    @Test
    void shouldReturnNoUserForUnknownToken() {
        assertThat(dir.getUser("unknown"), is(nullValue()));
    }

    @Test
    void shouldReturnUserForIssuedToken() {
        String token = dir.getToken("user");
        assertThat(dir.getUser(token), is(equalTo("user")));
    }

    @Test
    void shouldIssueTokenForNullUsername() {
        String token = dir.getToken(null);
        assertThat(token, is(notNullValue()));
        assertThat(dir.getUser(token), is(nullValue()));
    }
}
