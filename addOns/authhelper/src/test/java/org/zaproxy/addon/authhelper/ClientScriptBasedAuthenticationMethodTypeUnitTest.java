/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
package org.zaproxy.addon.authhelper;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.zaproxy.addon.authhelper.ClientScriptBasedAuthenticationMethodType.ClientScriptBasedAuthenticationMethod;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.utils.I18N;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

class ClientScriptBasedAuthenticationMethodTypeUnitTest {

    @BeforeAll
    static void beforeAll() {
        Constant.messages = mock(I18N.class);
        Control.initSingletonForTesting(mock(Model.class), mock(ExtensionLoader.class));
    }

    @Test
    void shouldLoadContextExportV0() {
        // Given
        ScriptWrapper scriptWrapper = mock(ScriptWrapper.class);
        given(scriptWrapper.getName()).willReturn("test_auth_script");

        ClientScriptBasedAuthenticationMethodType type =
                new ClientScriptBasedAuthenticationMethodType();
        ClientScriptBasedAuthenticationMethod method1 = type.createAuthenticationMethod(0);
        ZapXmlConfiguration config = new ZapXmlConfiguration();
        method1.setScriptWrapper(scriptWrapper);
        config.setProperty("context.authentication.script.loginpagewait", 2);
        // When
        assertDoesNotThrow(() -> method1.getType().importData(config, method1));
        // Then
        assertThat(method1.getLoginPageWait(), is(equalTo(2)));
        assertThat(method1.getMinWaitFor(), is(equalTo(0)));
    }
}
