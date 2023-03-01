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
package org.zaproxy.addon.authhelper;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.parosproxy.paros.db.RecordContext;
import org.parosproxy.paros.model.Session;
import org.zaproxy.addon.authhelper.BrowserBasedAuthenticationMethodType.BrowserBasedAuthenticationMethod;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

class BrowserBasedAuthenticationMethodTypeUnitTest {

    @Test
    void shouldExportAndImportData() throws Exception {
        // Given
        BrowserBasedAuthenticationMethodType type = new BrowserBasedAuthenticationMethodType();
        BrowserBasedAuthenticationMethod method1 = type.createAuthenticationMethod(0);
        BrowserBasedAuthenticationMethod method2 = type.createAuthenticationMethod(1);
        method1.setLoginPageUrl("https://www.example.com");
        method1.setLoginPageWait(7);
        method1.setBrowserId("example");
        ZapXmlConfiguration config = new ZapXmlConfiguration();

        // When
        method1.getType().exportData(config, method1);
        method2.getType().importData(config, method2);

        // Then
        assertThat(method2.getLoginPageUrl(), is(equalTo("https://www.example.com")));
        assertThat(method2.getLoginPageWait(), is(equalTo(7)));
        assertThat(method2.getBrowserId(), is(equalTo("example")));
    }

    @Test
    void shouldPersistAndLoadFromSession() throws Exception {
        // Given
        BrowserBasedAuthenticationMethodType type = new BrowserBasedAuthenticationMethodType();
        BrowserBasedAuthenticationMethod method1 = type.createAuthenticationMethod(0);
        BrowserBasedAuthenticationMethod method2 = type.createAuthenticationMethod(1);
        method1.setLoginPageUrl("https://www.example.com");
        method1.setLoginPageWait(7);
        method1.setBrowserId("example");
        Session session = mock(Session.class);
        ArgumentCaptor<String> valueCapture1 = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> valueCapture2 = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> valueCapture3 = ArgumentCaptor.forClass(String.class);

        doNothing()
                .when(session)
                .setContextData(
                        anyInt(),
                        eq(RecordContext.TYPE_AUTH_METHOD_FIELD_1),
                        valueCapture1.capture());
        doNothing()
                .when(session)
                .setContextData(
                        anyInt(),
                        eq(RecordContext.TYPE_AUTH_METHOD_FIELD_2),
                        valueCapture2.capture());
        doNothing()
                .when(session)
                .setContextData(
                        anyInt(),
                        eq(RecordContext.TYPE_AUTH_METHOD_FIELD_3),
                        valueCapture3.capture());

        method1.getType().persistMethodToSession(session, 1, method1);

        when(session.getContextDataString(1, RecordContext.TYPE_AUTH_METHOD_FIELD_1, ""))
                .thenReturn(valueCapture1.getValue());

        when(session.getContextDataString(
                        1,
                        RecordContext.TYPE_AUTH_METHOD_FIELD_2,
                        BrowserBasedAuthenticationMethodType.DEFAULT_BROWSER_ID))
                .thenReturn(valueCapture2.getValue());

        when(session.getContextDataString(1, RecordContext.TYPE_AUTH_METHOD_FIELD_3, ""))
                .thenReturn(valueCapture3.getValue());

        // When
        method2 =
                (BrowserBasedAuthenticationMethod)
                        method2.getType().loadMethodFromSession(session, 1);

        // Then
        assertThat(method2.getLoginPageUrl(), is(equalTo("https://www.example.com")));
        assertThat(method2.getLoginPageWait(), is(equalTo(7)));
        assertThat(method2.getBrowserId(), is(equalTo("example")));
    }
}
