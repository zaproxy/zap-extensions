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
package org.zaproxy.addon.oast.services.callback;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

class CallbackParamUnitTest {

    private CallbackParam param;

    @BeforeEach
    void setUp() {
        param = new CallbackParam();
        param.load(new ZapXmlConfiguration());
    }

    @Test
    void shouldIgnoreNullLocalAddress() {
        String localAddress = param.getLocalAddress();

        assertDoesNotThrow(() -> param.setLocalAddress(null));

        assertThat(param.getLocalAddress(), is(localAddress));
    }

    @Test
    void shouldIgnoreNullRemoteAddress() {
        String remoteAddress = param.getRemoteAddress();

        assertDoesNotThrow(() -> param.setRemoteAddress(null));

        assertThat(param.getRemoteAddress(), is(remoteAddress));
    }
}
