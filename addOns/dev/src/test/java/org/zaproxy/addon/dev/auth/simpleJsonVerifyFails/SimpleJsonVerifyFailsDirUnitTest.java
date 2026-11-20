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
package org.zaproxy.addon.dev.auth.simpleJsonVerifyFails;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.mock;

import org.junit.jupiter.api.Test;
import org.zaproxy.addon.dev.TestProxyServer;

/** Unit test for {@link SimpleJsonVerifyFailsDir}. */
class SimpleJsonVerifyFailsDirUnitTest {

    private final SimpleJsonVerifyFailsDir dir =
            new SimpleJsonVerifyFailsDir(mock(TestProxyServer.class), "dir");

    @Test
    void shouldAlwaysFailByDefault() {
        assertThat(dir.nextVerificationSucceeds(), is(false));
        assertThat(dir.nextVerificationSucceeds(), is(false));
    }

    @Test
    void shouldFailAfterSetNumberOfVerifications() {
        // Given
        dir.setFailAfter(2);
        // When / Then
        assertThat(dir.nextVerificationSucceeds(), is(true));
        assertThat(dir.nextVerificationSucceeds(), is(true));
        assertThat(dir.nextVerificationSucceeds(), is(false));
        assertThat(dir.nextVerificationSucceeds(), is(false));
    }

    @Test
    void shouldRestartCountWhenSettingFailAfter() {
        // Given
        dir.setFailAfter(1);
        dir.nextVerificationSucceeds();
        // When
        dir.setFailAfter(1);
        // Then
        assertThat(dir.nextVerificationSucceeds(), is(true));
    }

    @Test
    void shouldAlwaysFailWhenFailAfterIsZeroOrNegative() {
        dir.setFailAfter(-3);
        assertThat(dir.getFailAfter(), is(0));
        assertThat(dir.nextVerificationSucceeds(), is(false));
    }

    @Test
    void shouldRestartCountButKeepSettingOnReset() {
        // Given
        dir.setFailAfter(1);
        dir.nextVerificationSucceeds();
        // When
        dir.reset();
        // Then
        assertThat(dir.getFailAfter(), is(1));
        assertThat(dir.getVerifications(), is(0));
        assertThat(dir.nextVerificationSucceeds(), is(true));
    }
}
