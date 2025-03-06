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
package org.zaproxy.addon.authhelper.client;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

import org.junit.jupiter.api.Test;
import org.zaproxy.addon.authhelper.ExtensionAuthhelper;
import org.zaproxy.zap.testutils.TestUtils;

class ExtensionAuthhelperClientUnitTest extends TestUtils {

    @Test
    void shouldHaveName() {
        // Given
        ExtensionAuthhelperClient cl = new ExtensionAuthhelperClient();
        mockMessages(new ExtensionAuthhelper());
        // When / Then
        assertThat(cl.getName(), is(equalTo("ExtensionAuthhelperClient")));
    }

    @Test
    void shouldHaveUiName() {
        // Given
        ExtensionAuthhelperClient cl = new ExtensionAuthhelperClient();
        mockMessages(new ExtensionAuthhelper());
        // When / Then
        assertThat(
                cl.getUIName(), is(equalTo("Client Spider Browser Based Authentication Support")));
    }

    @Test
    void shouldBeUnloadable() {
        // Given
        ExtensionAuthhelperClient cl = new ExtensionAuthhelperClient();
        // When / Then
        assertThat(cl.canUnload(), is(equalTo(true)));
    }
}
