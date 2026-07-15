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
package org.zaproxy.addon.authhelper.llm;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.CoreMatchers.sameInstance;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import net.sf.json.JSONObject;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.mockito.ArgumentCaptor;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.db.RecordContext;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.zaproxy.addon.authhelper.llm.AiAssistedAuthenticationMethodType.AiAssistedAuthenticationMethod;
import org.zaproxy.addon.llm.ExtensionLlm;
import org.zaproxy.zap.authentication.AuthenticationMethod;
import org.zaproxy.zap.extension.api.ApiDynamicActionImplementor;
import org.zaproxy.zap.extension.api.ApiResponse;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.utils.I18N;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

class AiAssistedAuthenticationMethodTypeUnitTest {

    @AfterAll
    static void cleanUp() {
        Model.setSingletonForTesting(mock(Model.class));
    }

    @Nested
    class MethodIdentification {

        @Test
        void shouldHaveCorrectMethodIdentifier() {
            assertThat(AiAssistedAuthenticationMethodType.METHOD_IDENTIFIER, is(equalTo(9)));
        }

        @Test
        void shouldIdentifyItsOwnMethodType() {
            AiAssistedAuthenticationMethodType type = new AiAssistedAuthenticationMethodType();
            AiAssistedAuthenticationMethod method = type.createAuthenticationMethod(0);
            assertThat(type.isTypeForMethod(method), is(true));
        }

        @Test
        void shouldNotIdentifyOtherMethodTypes() {
            AiAssistedAuthenticationMethodType type = new AiAssistedAuthenticationMethodType();
            assertThat(type.isTypeForMethod(mock(AuthenticationMethod.class)), is(false));
        }
    }

    @Nested
    class Configuration {

        @Test
        void shouldNotBeConfiguredByDefault() {
            AiAssistedAuthenticationMethod method =
                    new AiAssistedAuthenticationMethodType().createAuthenticationMethod(0);
            assertThat(method.isConfigured(), is(false));
        }

        @Test
        void shouldBeConfiguredOnceUrlIsSet() {
            AiAssistedAuthenticationMethod method =
                    new AiAssistedAuthenticationMethodType().createAuthenticationMethod(0);
            method.setLoginPageUrl("https://www.example.com/login");
            assertThat(method.isConfigured(), is(true));
        }

        @Test
        void shouldNotBeConfiguredWithBlankUrl() {
            AiAssistedAuthenticationMethod method =
                    new AiAssistedAuthenticationMethodType().createAuthenticationMethod(0);
            method.setLoginPageUrl("   ");
            assertThat(method.isConfigured(), is(false));
        }
    }

    @Nested
    class CheckPrerequisites {

        private ExtensionLoader extensionLoader;
        private ExtensionLlm extLlm;
        private AiAssistedAuthenticationMethod method;

        @BeforeEach
        void setUp() {
            Constant.messages = mock(I18N.class);
            extensionLoader = mock(ExtensionLoader.class);
            Control.initSingletonForTesting(mock(Model.class), extensionLoader);
            extLlm = mock(ExtensionLlm.class);
            given(extensionLoader.getExtension(ExtensionLlm.class)).willReturn(extLlm);
            given(Constant.messages.getString("authhelper.auth.method.ai.error.llm.notconfigured"))
                    .willReturn(
                            "No LLM provider is configured. Configure this in the LLM Options.");
            method = new AiAssistedAuthenticationMethodType().createAuthenticationMethod(0);
        }

        @Test
        void shouldReturnNullWhenLlmIsConfigured() {
            given(extLlm.isConfigured()).willReturn(true);

            String issue = method.checkPrerequisites();

            assertThat(issue, is(nullValue()));
        }

        @Test
        void shouldReportIssueWhenLlmNotConfigured() {
            given(extLlm.isConfigured()).willReturn(false);

            String issue = method.checkPrerequisites();

            assertThat(
                    issue,
                    is(
                            equalTo(
                                    "No LLM provider is configured. Configure this in the LLM"
                                            + " Options.")));
        }
    }

    @Nested
    class FieldDefaultsAndDuplication {

        @ParameterizedTest
        @NullAndEmptySource
        void shouldNotOverrideBrowserIdWithNullOrEmpty(String value) {
            AiAssistedAuthenticationMethod method =
                    new AiAssistedAuthenticationMethodType().createAuthenticationMethod(0);
            String defaultId = method.getBrowserId();
            method.setBrowserId(value);
            assertThat(method.getBrowserId(), is(equalTo(defaultId)));
        }

        @Test
        void shouldTreatNullHintAsEmpty() {
            AiAssistedAuthenticationMethod method =
                    new AiAssistedAuthenticationMethodType().createAuthenticationMethod(0);
            method.setHint(null);
            assertThat(method.getHint(), is(equalTo("")));
        }

        @Test
        void shouldDuplicateAllFields() {
            AiAssistedAuthenticationMethodType type = new AiAssistedAuthenticationMethodType();
            AiAssistedAuthenticationMethod original = type.createAuthenticationMethod(0);
            original.setLoginPageUrl("https://www.example.com/login");
            original.setBrowserId("firefox");
            original.setLoginPageWait(10);
            original.setHint("The domain dropdown must be set to Project1");

            AiAssistedAuthenticationMethod copy =
                    (AiAssistedAuthenticationMethod) original.duplicate();

            assertThat(copy, is(not(sameInstance(original))));
            assertThat(copy.getLoginPageUrl(), is(equalTo("https://www.example.com/login")));
            assertThat(copy.getBrowserId(), is(equalTo("firefox")));
            assertThat(copy.getLoginPageWait(), is(equalTo(10)));
            assertThat(copy.getHint(), is(equalTo("The domain dropdown must be set to Project1")));
        }
    }

    @Nested
    class Api {

        @Test
        void shouldBeConfiguredThroughTheApi() throws Exception {
            ApiDynamicActionImplementor api =
                    new AiAssistedAuthenticationMethodType().getSetMethodForContextApiAction();
            Model model = mock(Model.class);
            Model.setSingletonForTesting(model);
            Session session = mock(Session.class);
            given(model.getSession()).willReturn(session);
            int contextId = 1;
            Context context = new Context(session, contextId);
            given(session.getContext(contextId)).willReturn(context);

            JSONObject params = new JSONObject();
            params.put("contextId", contextId);
            params.put("loginPageUrl", "https://www.example.com/login");
            params.put("browserId", "firefox");
            params.put("loginPageWait", "8");
            params.put("hint", "Select Project1 in the domain dropdown");

            api.handleAction(params);

            AuthenticationMethod method = context.getAuthenticationMethod();
            assertThat(method, is(instanceOf(AiAssistedAuthenticationMethod.class)));
            AiAssistedAuthenticationMethod ai = (AiAssistedAuthenticationMethod) method;
            assertThat(ai.getLoginPageUrl(), is(equalTo("https://www.example.com/login")));
            assertThat(ai.getBrowserId(), is(equalTo("firefox")));
            assertThat(ai.getLoginPageWait(), is(equalTo(8)));
            assertThat(ai.getHint(), is(equalTo("Select Project1 in the domain dropdown")));
        }

        @Test
        void shouldBeConfiguredThroughTheApiWithOnlyMandatoryParams() throws Exception {
            ApiDynamicActionImplementor api =
                    new AiAssistedAuthenticationMethodType().getSetMethodForContextApiAction();
            Model model = mock(Model.class);
            Model.setSingletonForTesting(model);
            Session session = mock(Session.class);
            given(model.getSession()).willReturn(session);
            int contextId = 1;
            Context context = new Context(session, contextId);
            given(session.getContext(contextId)).willReturn(context);

            JSONObject params = new JSONObject();
            params.put("contextId", contextId);
            params.put("loginPageUrl", "https://www.example.com/login");

            api.handleAction(params);

            AuthenticationMethod method = context.getAuthenticationMethod();
            assertThat(method, is(instanceOf(AiAssistedAuthenticationMethod.class)));
            AiAssistedAuthenticationMethod ai = (AiAssistedAuthenticationMethod) method;
            assertThat(ai.getLoginPageUrl(), is(equalTo("https://www.example.com/login")));
            assertThat(
                    ai.getBrowserId(),
                    is(equalTo(AiAssistedAuthenticationMethodType.DEFAULT_BROWSER_ID)));
            assertThat(ai.getLoginPageWait(), is(equalTo(5)));
            assertThat(ai.getHint(), is(equalTo("")));
        }

        @Test
        void shouldGetConfigurationThroughTheApi() {
            AiAssistedAuthenticationMethod method =
                    new AiAssistedAuthenticationMethodType().createAuthenticationMethod(0);
            method.setLoginPageUrl("https://www.example.com/login");
            method.setBrowserId("firefox");
            method.setLoginPageWait(8);
            method.setHint("Select Project1 in the domain dropdown");

            ApiResponse response = method.getApiResponseRepresentation();

            String expectedResponse =
                    """
                    {"method":{"browserId":"firefox","loginPageWait":8,"hint":"Select Project1 in the domain dropdown","loginPageUrl":"https://www.example.com/login"}}""";
            assertThat(response.toJSON().toString(), is(equalTo(expectedResponse)));
        }
    }

    @Nested
    class ConfigurationExportImport {

        @Test
        void shouldExportAndImportData() throws Exception {
            AiAssistedAuthenticationMethodType type = new AiAssistedAuthenticationMethodType();
            AiAssistedAuthenticationMethod method1 = type.createAuthenticationMethod(0);
            AiAssistedAuthenticationMethod method2 = type.createAuthenticationMethod(1);
            method1.setLoginPageUrl("https://www.example.com/login");
            method1.setBrowserId("firefox");
            method1.setLoginPageWait(8);
            method1.setHint("Select Project1 in the domain dropdown");
            ZapXmlConfiguration config = new ZapXmlConfiguration();

            method1.getType().exportData(config, method1);
            method2.getType().importData(config, method2);

            assertThat(method2.getLoginPageUrl(), is(equalTo("https://www.example.com/login")));
            assertThat(method2.getBrowserId(), is(equalTo("firefox")));
            assertThat(method2.getLoginPageWait(), is(equalTo(8)));
            assertThat(method2.getHint(), is(equalTo("Select Project1 in the domain dropdown")));
        }

        @Test
        void shouldExportAndImportEmptyHint() throws Exception {
            AiAssistedAuthenticationMethodType type = new AiAssistedAuthenticationMethodType();
            AiAssistedAuthenticationMethod method1 = type.createAuthenticationMethod(0);
            AiAssistedAuthenticationMethod method2 = type.createAuthenticationMethod(1);
            method1.setLoginPageUrl("https://www.example.com/login");
            ZapXmlConfiguration config = new ZapXmlConfiguration();

            method1.getType().exportData(config, method1);
            method2.getType().importData(config, method2);

            assertThat(method2.getHint(), is(equalTo("")));
        }
    }

    @Nested
    class SessionPersistence {

        @Test
        void shouldPersistAndLoadFromSession() throws Exception {
            AiAssistedAuthenticationMethodType type = new AiAssistedAuthenticationMethodType();
            AiAssistedAuthenticationMethod method1 = type.createAuthenticationMethod(0);
            method1.setLoginPageUrl("https://www.example.com/login");
            method1.setBrowserId("firefox");
            method1.setLoginPageWait(8);
            method1.setHint("Select Project1 in the domain dropdown");

            Session session = mock(Session.class);
            ArgumentCaptor<String> field1 = ArgumentCaptor.forClass(String.class);
            ArgumentCaptor<String> field2 = ArgumentCaptor.forClass(String.class);
            ArgumentCaptor<String> field3 = ArgumentCaptor.forClass(String.class);
            ArgumentCaptor<String> field4 = ArgumentCaptor.forClass(String.class);

            doNothing()
                    .when(session)
                    .setContextData(
                            anyInt(), eq(RecordContext.TYPE_AUTH_METHOD_FIELD_1), field1.capture());
            doNothing()
                    .when(session)
                    .setContextData(
                            anyInt(), eq(RecordContext.TYPE_AUTH_METHOD_FIELD_2), field2.capture());
            doNothing()
                    .when(session)
                    .setContextData(
                            anyInt(), eq(RecordContext.TYPE_AUTH_METHOD_FIELD_3), field3.capture());
            doNothing()
                    .when(session)
                    .setContextData(
                            anyInt(), eq(RecordContext.TYPE_AUTH_METHOD_FIELD_4), field4.capture());

            method1.getType().persistMethodToSession(session, 1, method1);

            when(session.getContextDataString(1, RecordContext.TYPE_AUTH_METHOD_FIELD_1, ""))
                    .thenReturn(field1.getValue());
            when(session.getContextDataString(
                            1,
                            RecordContext.TYPE_AUTH_METHOD_FIELD_2,
                            AiAssistedAuthenticationMethodType.DEFAULT_BROWSER_ID))
                    .thenReturn(field2.getValue());
            when(session.getContextDataString(1, RecordContext.TYPE_AUTH_METHOD_FIELD_3, ""))
                    .thenReturn(field3.getValue());
            when(session.getContextDataString(1, RecordContext.TYPE_AUTH_METHOD_FIELD_4, ""))
                    .thenReturn(field4.getValue());

            AiAssistedAuthenticationMethod method2 =
                    (AiAssistedAuthenticationMethod) type.loadMethodFromSession(session, 1);

            assertThat(method2.getLoginPageUrl(), is(equalTo("https://www.example.com/login")));
            assertThat(method2.getBrowserId(), is(equalTo("firefox")));
            assertThat(method2.getLoginPageWait(), is(equalTo(8)));
            assertThat(method2.getHint(), is(equalTo("Select Project1 in the domain dropdown")));
        }

        @Test
        void shouldLoadDefaultsFromSessionWhenFieldsAbsent() throws Exception {
            AiAssistedAuthenticationMethodType type = new AiAssistedAuthenticationMethodType();
            Session session = mock(Session.class);
            when(session.getContextDataString(1, RecordContext.TYPE_AUTH_METHOD_FIELD_1, ""))
                    .thenReturn("");
            when(session.getContextDataString(
                            1,
                            RecordContext.TYPE_AUTH_METHOD_FIELD_2,
                            AiAssistedAuthenticationMethodType.DEFAULT_BROWSER_ID))
                    .thenReturn(AiAssistedAuthenticationMethodType.DEFAULT_BROWSER_ID);
            when(session.getContextDataString(1, RecordContext.TYPE_AUTH_METHOD_FIELD_3, ""))
                    .thenReturn("");
            when(session.getContextDataString(1, RecordContext.TYPE_AUTH_METHOD_FIELD_4, ""))
                    .thenReturn("");

            AiAssistedAuthenticationMethod method =
                    (AiAssistedAuthenticationMethod) type.loadMethodFromSession(session, 1);

            assertThat(method.getLoginPageUrl(), is(equalTo("")));
            assertThat(
                    method.getBrowserId(),
                    is(equalTo(AiAssistedAuthenticationMethodType.DEFAULT_BROWSER_ID)));
            assertThat(method.getLoginPageWait(), is(equalTo(5)));
            assertThat(method.getHint(), is(equalTo("")));
        }
    }
}
