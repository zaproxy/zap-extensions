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
package org.zaproxy.addon.authhelpertest;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.mock;

import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.zaproxy.addon.dev.ExtensionDev;
import org.zaproxy.addon.dev.TestProxyServer;
import org.zaproxy.addon.network.ExtensionNetwork;

/** Unit test for {@link ExtensionAuthhelperTest}. */
class ExtensionAuthhelperTestUnitTest {

    private final TestProxyServer server =
            new TestProxyServer(mock(ExtensionDev.class), mock(ExtensionNetwork.class));

    @Test
    void shouldPlugMultiStepAuth() {
        // Given
        ExtensionAuthhelperTest extension = new ExtensionAuthhelperTest(() -> Optional.of(server));
        // When
        extension.optionsLoaded();
        // Then
        assertThat(server.removeDirectory("auth/multi-step-auth"), is(true));
    }

    @Test
    void shouldUnplugMultiStepAuth() {
        // Given
        ExtensionAuthhelperTest extension = new ExtensionAuthhelperTest(() -> Optional.of(server));
        extension.optionsLoaded();
        // When
        extension.unload();
        // Then
        assertThat(server.removeDirectory("auth/multi-step-auth"), is(false));
    }

    @Test
    void shouldDoNothingWithoutServer() {
        // Given
        ExtensionAuthhelperTest extension = new ExtensionAuthhelperTest(Optional::empty);
        // When / Then
        extension.optionsLoaded();
        extension.unload();
    }
}
