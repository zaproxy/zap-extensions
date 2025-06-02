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
package org.zaproxy.addon.automation;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Locale;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.session.CookieBasedSessionManagementMethodType.CookieBasedSessionManagementMethod;
import org.zaproxy.zap.session.HttpAuthSessionManagementMethodType.HttpAuthSessionManagementMethod;
import org.zaproxy.zap.session.ScriptBasedSessionManagementMethodType;
import org.zaproxy.zap.utils.I18N;

class SessionManagementDataUnitTest {

    @Test
    void shouldSetCookieMethod() {
        // Given
        Context context = mock(Context.class);
        when(context.getSessionManagementMethod())
                .thenReturn(new CookieBasedSessionManagementMethod(0));

        // When
        SessionManagementData smd = new SessionManagementData(context);

        // Then
        assertThat(smd.getMethod(), is(equalTo("cookie")));
    }

    @Test
    void shouldSetHttpAuthMethod() {
        // Given
        Context context = mock(Context.class);
        when(context.getSessionManagementMethod())
                .thenReturn(new HttpAuthSessionManagementMethod());

        // When
        SessionManagementData smd = new SessionManagementData(context);

        // Then
        assertThat(smd.getMethod(), is(equalTo("http")));
    }

    @Test
    void shouldSetScriptMethod() {
        // Given
        Constant.messages = new I18N(Locale.ENGLISH);
        Context context = mock(Context.class);
        ScriptBasedSessionManagementMethodType scriptType =
                new ScriptBasedSessionManagementMethodType();

        when(context.getSessionManagementMethod())
                .thenReturn(scriptType.createSessionManagementMethod(0));

        // When
        SessionManagementData smd = new SessionManagementData(context);

        // Then
        assertThat(smd.getMethod(), is(equalTo("script")));
    }
}
