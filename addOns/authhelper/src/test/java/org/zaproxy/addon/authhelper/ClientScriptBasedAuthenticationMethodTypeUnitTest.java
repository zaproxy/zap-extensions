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
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.spy;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.authhelper.ClientScriptBasedAuthenticationMethodType.ClientScriptBasedAuthenticationMethod;
import org.zaproxy.zap.authentication.AuthenticationHelper;
import org.zaproxy.zap.authentication.GenericAuthenticationCredentials;
import org.zaproxy.zap.authentication.ScriptBasedAuthenticationMethodType;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.session.SessionManagementMethod;
import org.zaproxy.zap.users.User;
import org.zaproxy.zap.utils.I18N;
import org.zaproxy.zap.utils.ZapXmlConfiguration;
import org.zaproxy.zest.core.v1.ZestClientLaunch;
import org.zaproxy.zest.core.v1.ZestScript;

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

    @Test
    void shouldGetMessageFromFirstEnabledZestClientLaunch() throws Exception {
        // Given
        ZestScript script = new ZestScript();

        ZestClientLaunch cl =
                new ZestClientLaunch(
                        "window", "firefox", "https://app1.example.com/login", null, true, null);
        cl.setEnabled(false);
        script.add(cl);
        script.add(
                new ZestClientLaunch(
                        "w2", "firefox", "https://app2.example.com/login", null, true, null));
        script.add(
                new ZestClientLaunch(
                        "w3", "firefox", "https://app3.example.com/login", null, true, null));

        // When
        HttpMessage msg = ClientScriptBasedAuthenticationMethod.getFirstMessage(script, mock());

        // Then
        assertThat(msg, is(notNullValue()));
        assertThat(
                msg.getRequestHeader().getURI().toString(),
                equalTo("https://app2.example.com/login"));
    }

    @Test
    void shouldFallbackToUnknownUrlWhenNoZestClientLaunch() throws Exception {
        // Given
        ZestScript script = new ZestScript();

        // When
        HttpMessage msg = ClientScriptBasedAuthenticationMethod.getFirstMessage(script, mock());

        // Then
        assertThat(msg, is(notNullValue()));
        assertThat(
                msg.getRequestHeader().getURI().toString(),
                equalTo("https://unknown-auth-url.zap/"));
    }

    @Test
    void shouldNotifyFailureWhenNoScriptOnWebDriverAuth() {
        // Given
        ClientScriptBasedAuthenticationMethod method =
                spy(new ClientScriptBasedAuthenticationMethodType().createAuthenticationMethod(0));
        doReturn(null).when(method).getZestScript();

        try (MockedStatic<AuthenticationHelper> authMock = mockStatic()) {
            // When
            boolean result = method.authenticate(mock(), mock());

            // Then
            assertThat(result, is(false));
            authMock.verify(() -> AuthenticationHelper.notifyOutputAuthFailure(any()));
        }
    }

    @Test
    void shouldNotifyFailureOnExceptionOnWebDriverAuth() {
        // Given
        ZestScript script = new ZestScript();
        script.add(
                new ZestClientLaunch(
                        "window", "firefox", "https://app.example.com/login", null, true, null));

        ClientScriptBasedAuthenticationMethod method =
                spy(new ClientScriptBasedAuthenticationMethodType().createAuthenticationMethod(0));
        doReturn(script).when(method).getZestScript();

        try (MockedStatic<AuthenticationHelper> authMock = mockStatic()) {
            // When
            boolean result = method.authenticate(mock(), mock());

            // Then
            assertThat(result, is(false));
            authMock.verify(() -> AuthenticationHelper.notifyOutputAuthFailure(any()));
        }
    }

    @Test
    @SuppressWarnings("try")
    void shouldNotifyFailureWhenAuthScriptIsNullOnUserAuth() throws Exception {
        // Given
        ClientScriptBasedAuthenticationMethod method =
                new ClientScriptBasedAuthenticationMethodType().createAuthenticationMethod(0);

        ScriptWrapper scriptWrapper = mock();
        given(scriptWrapper.getName()).willReturn("test_script");
        method.setScriptWrapper(scriptWrapper);

        User user = mock();
        SessionManagementMethod sessionMgmt = mock();
        GenericAuthenticationCredentials credentials = mock();

        try (MockedStatic<ScriptBasedAuthenticationMethodType> ignored = mockStatic();
                MockedStatic<AuthenticationHelper> authMock = mockStatic()) {

            // When
            var result = method.authenticate(sessionMgmt, credentials, user);

            // Then
            assertThat(result, is(nullValue()));
            authMock.verify(() -> AuthenticationHelper.notifyOutputAuthFailure(any()));
        }
    }
}
