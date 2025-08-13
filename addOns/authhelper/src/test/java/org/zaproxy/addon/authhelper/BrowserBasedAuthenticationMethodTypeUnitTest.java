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
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import net.sf.json.JSONObject;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.parosproxy.paros.db.RecordContext;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.zaproxy.addon.authhelper.BrowserBasedAuthenticationMethodType.BrowserBasedAuthenticationMethod;
import org.zaproxy.zap.authentication.AuthenticationMethod;
import org.zaproxy.zap.extension.api.ApiDynamicActionImplementor;
import org.zaproxy.zap.extension.api.ApiResponse;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

class BrowserBasedAuthenticationMethodTypeUnitTest {

    @AfterAll
    static void cleanUp() {
        Model.setSingletonForTesting(new Model());
    }

    @Test
    void shouldBeConfiguredThroughTheApi() throws Exception {
        // Given
        ApiDynamicActionImplementor api =
                new BrowserBasedAuthenticationMethodType().getSetMethodForContextApiAction();
        Model model = mock(Model.class);
        Model.setSingletonForTesting(model);
        Session session = mock(Session.class);
        given(model.getSession()).willReturn(session);
        int contextId = 1;
        Context context = new Context(session, contextId);
        given(session.getContext(contextId)).willReturn(context);

        JSONObject params = new JSONObject();
        params.put("contextId", contextId);
        params.put("loginPageUrl", "https://www.example.com");
        params.put("browserId", "example");
        params.put("loginPageWait", "7");
        params.put("stepDelay", "2");

        // When
        api.handleAction(params);

        // Then
        AuthenticationMethod method = context.getAuthenticationMethod();
        assertThat(method, is(instanceOf(BrowserBasedAuthenticationMethod.class)));
        BrowserBasedAuthenticationMethod bba = (BrowserBasedAuthenticationMethod) method;
        assertThat(bba.getLoginPageUrl(), is(equalTo("https://www.example.com")));
        assertThat(bba.getLoginPageWait(), is(equalTo(7)));
        assertThat(bba.getStepDelay(), is(equalTo(2)));
        assertThat(bba.getBrowserId(), is(equalTo("example")));
    }

    @Test
    void shouldGetConfigurationThroughTheApi() {
        // Given
        BrowserBasedAuthenticationMethod method =
                new BrowserBasedAuthenticationMethodType().createAuthenticationMethod(0);
        method.setLoginPageUrl("https://www.example.com");
        method.setLoginPageWait(7);
        method.setStepDelay(1);
        method.setBrowserId("example");

        // When
        ApiResponse response = method.getApiResponseRepresentation();

        // The
        String expectedResponse =
                """
                {"method":{"browserId":"example","loginPageWait":7,"loginPageUrl":"https://www.example.com","stepDelay":1}}""";
        assertThat(response.toJSON().toString(), is(equalTo(expectedResponse)));
    }

    @Test
    void shouldExportAndImportData() throws Exception {
        // Given
        BrowserBasedAuthenticationMethodType type = new BrowserBasedAuthenticationMethodType();
        BrowserBasedAuthenticationMethod method1 = type.createAuthenticationMethod(0);
        BrowserBasedAuthenticationMethod method2 = type.createAuthenticationMethod(1);
        method1.setLoginPageUrl("https://www.example.com");
        method1.setLoginPageWait(7);
        method1.setStepDelay(3);
        method1.setBrowserId("example");
        ZapXmlConfiguration config = new ZapXmlConfiguration();

        // When
        method1.getType().exportData(config, method1);
        method2.getType().importData(config, method2);

        // Then
        assertThat(method2.getLoginPageUrl(), is(equalTo("https://www.example.com")));
        assertThat(method2.getLoginPageWait(), is(equalTo(7)));
        assertThat(method2.getStepDelay(), is(equalTo(3)));
        assertThat(method2.getBrowserId(), is(equalTo("example")));
    }

    @Test
    void shouldLoadContextExportV0() {
        // Given
        String loginUrl = "https://www.example.com";
        BrowserBasedAuthenticationMethodType type = new BrowserBasedAuthenticationMethodType();
        BrowserBasedAuthenticationMethod method1 = type.createAuthenticationMethod(0);
        ZapXmlConfiguration config = new ZapXmlConfiguration();
        config.setProperty("context.authentication.browser.loginpageurl", loginUrl);
        config.setProperty("context.authentication.browser.loginpagewait", 2);
        // When
        assertDoesNotThrow(() -> method1.getType().importData(config, method1));
        // Then
        assertThat(method1.getLoginPageUrl(), is(equalTo(loginUrl)));
        assertThat(method1.getLoginPageWait(), is(equalTo(2)));
        assertThat(method1.getStepDelay(), is(equalTo(0)));
    }

    @Test
    void shouldPersistAndLoadFromSession() throws Exception {
        // Given
        BrowserBasedAuthenticationMethodType type = new BrowserBasedAuthenticationMethodType();
        BrowserBasedAuthenticationMethod method1 = type.createAuthenticationMethod(0);
        BrowserBasedAuthenticationMethod method2 = type.createAuthenticationMethod(1);
        method1.setLoginPageUrl("https://www.example.com");
        method1.setLoginPageWait(7);
        method1.setStepDelay(2);
        method1.setBrowserId("example");
        Session session = mock(Session.class);
        ArgumentCaptor<String> valueCapture1 = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> valueCapture2 = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> valueCapture3 = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> valueCapture4 = ArgumentCaptor.forClass(String.class);

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
        doNothing()
                .when(session)
                .setContextData(
                        anyInt(),
                        eq(RecordContext.TYPE_AUTH_METHOD_FIELD_5),
                        valueCapture4.capture());

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

        when(session.getContextDataString(1, RecordContext.TYPE_AUTH_METHOD_FIELD_5, ""))
                .thenReturn(valueCapture4.getValue());

        // When
        method2 =
                (BrowserBasedAuthenticationMethod)
                        method2.getType().loadMethodFromSession(session, 1);

        // Then
        assertThat(method2.getLoginPageUrl(), is(equalTo("https://www.example.com")));
        assertThat(method2.getLoginPageWait(), is(equalTo(7)));
        assertThat(method2.getBrowserId(), is(equalTo("example")));
        assertThat(method2.getStepDelay(), is(equalTo(2)));
    }
}
