/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.automation.jobs.JobUtils;
import org.zaproxy.zap.authentication.AuthenticationMethod;
import org.zaproxy.zap.authentication.FormBasedAuthenticationMethodType;
import org.zaproxy.zap.authentication.FormBasedAuthenticationMethodType.FormBasedAuthenticationMethod;
import org.zaproxy.zap.authentication.HttpAuthenticationMethodType.HttpAuthenticationMethod;
import org.zaproxy.zap.authentication.JsonBasedAuthenticationMethodType;
import org.zaproxy.zap.authentication.JsonBasedAuthenticationMethodType.JsonBasedAuthenticationMethod;
import org.zaproxy.zap.authentication.ScriptBasedAuthenticationMethodType;
import org.zaproxy.zap.authentication.ScriptBasedAuthenticationMethodType.ScriptBasedAuthenticationMethod;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.utils.I18N;

class AuthenticationDataUnitTest {

    private static final String TEST_URL_1 = "https://www.example.com/login1";
    private static final String TEST_URL_2 = "https://www.example.com/login2";
    private static final String TEST_FORM_DATA = "username={%username%}&password={%password%}";
    private static final String TEST_JSON_DATA =
            "{\"email\":\"{%username%}\",\"password\":\"{%password%}\"}";

    @Test
    void shouldCreateDataFromContextWithNoAuth() {
        // Given
        Constant.messages = new I18N(Locale.ENGLISH);
        Context context = mock(Context.class);

        // When
        AuthenticationData data = new AuthenticationData(context);
        Map<String, Object> params = data.getParameters();

        // Then
        assertThat(data.getVerification(), is(nullValue()));
        assertThat(data.getMethod(), is(nullValue()));
        assertThat(params.size(), is(equalTo(0)));
    }

    @Test
    void shouldCreateDataFromContextWithHttpAuth() {
        // Given
        HttpAuthenticationMethod httpAuthMethod = new HttpAuthenticationMethod();
        httpAuthMethod.setHostname("https://www.example.com");
        httpAuthMethod.setRealm("realm");
        httpAuthMethod.setPort(123);
        Constant.messages = new I18N(Locale.ENGLISH);
        Context context = mock(Context.class);
        given(context.getAuthenticationMethod()).willReturn(httpAuthMethod);

        // When
        AuthenticationData data = new AuthenticationData(context);
        Map<String, Object> params = data.getParameters();

        // Then
        assertThat(data.getVerification(), is(notNullValue()));
        assertThat(data.getMethod(), is(equalTo("http")));
        assertThat(params.size(), is(equalTo(3)));
        assertThat(
                params.get(AuthenticationData.PARAM_HOSTNAME),
                is(equalTo("https://www.example.com")));
        assertThat(params.get(AuthenticationData.PARAM_REALM), is(equalTo("realm")));
        assertThat(params.get(AuthenticationData.PARAM_PORT), is(equalTo(123)));
    }

    @Test
    void shouldCreateDataFromContextWithFormAuth() {
        // Given
        FormBasedAuthenticationMethodType formType = new FormBasedAuthenticationMethodType();
        FormBasedAuthenticationMethod formAuthMethod = formType.createAuthenticationMethod(-1);

        JobUtils.setPrivateField(
                formAuthMethod, AuthenticationData.PARAM_LOGIN_PAGE_URL, TEST_URL_1);
        JobUtils.setPrivateField(
                formAuthMethod, AuthenticationData.FIELD_LOGIN_REQUEST_URL, TEST_URL_2);
        JobUtils.setPrivateField(
                formAuthMethod, AuthenticationData.PARAM_LOGIN_REQUEST_BODY, TEST_FORM_DATA);

        Constant.messages = new I18N(Locale.ENGLISH);
        Context context = mock(Context.class);
        given(context.getAuthenticationMethod()).willReturn(formAuthMethod);

        // When
        AuthenticationData data = new AuthenticationData(context);
        Map<String, Object> params = data.getParameters();

        // Then
        assertThat(data.getVerification(), is(notNullValue()));
        assertThat(data.getMethod(), is(equalTo("form")));
        assertThat(params.size(), is(equalTo(3)));
        assertThat(params.get(AuthenticationData.PARAM_LOGIN_PAGE_URL), is(equalTo(TEST_URL_1)));
        assertThat(params.get(AuthenticationData.PARAM_LOGIN_REQUEST_URL), is(equalTo(TEST_URL_2)));
        assertThat(
                params.get(AuthenticationData.PARAM_LOGIN_REQUEST_BODY),
                is(equalTo(TEST_FORM_DATA)));
    }

    @Test
    void shouldCreateDataFromContextWithJsonAuth() {
        // Given
        JsonBasedAuthenticationMethodType jsonType = new JsonBasedAuthenticationMethodType();
        JsonBasedAuthenticationMethod jsonAuthMethod = jsonType.createAuthenticationMethod(-1);

        JobUtils.setPrivateField(
                jsonAuthMethod, AuthenticationData.PARAM_LOGIN_PAGE_URL, TEST_URL_1);
        JobUtils.setPrivateField(
                jsonAuthMethod, AuthenticationData.FIELD_LOGIN_REQUEST_URL, TEST_URL_2);
        JobUtils.setPrivateField(
                jsonAuthMethod, AuthenticationData.PARAM_LOGIN_REQUEST_BODY, TEST_FORM_DATA);

        Constant.messages = new I18N(Locale.ENGLISH);
        Context context = mock(Context.class);
        given(context.getAuthenticationMethod()).willReturn(jsonAuthMethod);

        // When
        AuthenticationData data = new AuthenticationData(context);
        Map<String, Object> params = data.getParameters();

        // Then
        assertThat(data.getVerification(), is(notNullValue()));
        assertThat(data.getMethod(), is(equalTo("json")));
        assertThat(params.size(), is(equalTo(3)));
        assertThat(params.get(AuthenticationData.PARAM_LOGIN_PAGE_URL), is(equalTo(TEST_URL_1)));
        assertThat(params.get(AuthenticationData.PARAM_LOGIN_REQUEST_URL), is(equalTo(TEST_URL_2)));
        assertThat(
                params.get(AuthenticationData.PARAM_LOGIN_REQUEST_BODY),
                is(equalTo(TEST_FORM_DATA)));
    }

    @Test
    void shouldCreateDataFromContextWithScriptAuth() throws IOException {
        // Given
        Constant.messages = new I18N(Locale.ENGLISH);
        ScriptBasedAuthenticationMethodType scriptType = new ScriptBasedAuthenticationMethodType();
        ScriptBasedAuthenticationMethod scriptAuthMethod =
                scriptType.createAuthenticationMethod(-1);

        ScriptWrapper scriptWrapper = mock(ScriptWrapper.class);
        File scriptFile = File.createTempFile("scriptAuthTest", ".js");
        given(scriptWrapper.getFile()).willReturn(scriptFile);

        Map<String, String> paramValues = new HashMap<>();
        paramValues.put("field1", "value1");
        paramValues.put("field2", "value2");

        JobUtils.setPrivateField(scriptAuthMethod, "script", scriptWrapper);
        JobUtils.setPrivateField(scriptAuthMethod, "paramValues", paramValues);

        Context context = mock(Context.class);
        given(context.getAuthenticationMethod()).willReturn(scriptAuthMethod);

        // When
        AuthenticationData data = new AuthenticationData(context);
        Map<String, Object> params = data.getParameters();

        // Then
        assertThat(data.getVerification(), is(notNullValue()));
        assertThat(data.getMethod(), is(equalTo("script")));
        // The script should be returned as well but mocking everything required is hard :/
        assertThat(params.get("field1"), is(equalTo("value1")));
        assertThat(params.get("field2"), is(equalTo("value2")));
    }

    @Test
    void shouldInitContextWithHttpAuth() {
        // Given
        Constant.messages = new I18N(Locale.ENGLISH);
        Context context = new Context(null, -1);

        AuthenticationData data = new AuthenticationData();
        data.setMethod("http");
        data.getParameters().put(AuthenticationData.PARAM_HOSTNAME, "https://www.example.com");
        data.getParameters().put(AuthenticationData.PARAM_REALM, "realm");
        data.getParameters().put(AuthenticationData.PARAM_PORT, 123);

        AutomationProgress progress = new AutomationProgress();
        AutomationEnvironment env = new AutomationEnvironment(progress);

        // When
        data.initContextAuthentication(context, progress, env);
        AuthenticationMethod authMethod = context.getAuthenticationMethod();

        // Then
        assertThat(authMethod, is(notNullValue()));
        assertThat(authMethod.getClass(), is(equalTo(HttpAuthenticationMethod.class)));
        HttpAuthenticationMethod method = (HttpAuthenticationMethod) authMethod;
        assertThat(
                JobUtils.getPrivateField(method, AuthenticationData.PARAM_HOSTNAME),
                is(equalTo("https://www.example.com")));
        assertThat(
                JobUtils.getPrivateField(method, AuthenticationData.PARAM_REALM),
                is(equalTo("realm")));
        assertThat(
                JobUtils.getPrivateField(method, AuthenticationData.PARAM_PORT), is(equalTo(123)));
    }

    @Test
    void shouldInitContextWithFormAuth() {
        // Given
        Constant.messages = new I18N(Locale.ENGLISH);
        Context context = new Context(null, -1);

        AuthenticationData data = new AuthenticationData();
        data.setMethod("form");
        data.getParameters().put(AuthenticationData.PARAM_LOGIN_PAGE_URL, TEST_URL_1);
        data.getParameters().put(AuthenticationData.PARAM_LOGIN_REQUEST_URL, TEST_URL_2);
        data.getParameters().put(AuthenticationData.PARAM_LOGIN_REQUEST_BODY, TEST_FORM_DATA);

        AutomationProgress progress = new AutomationProgress();
        AutomationEnvironment env = new AutomationEnvironment(progress);

        // When
        data.initContextAuthentication(context, progress, env);
        AuthenticationMethod authMethod = context.getAuthenticationMethod();

        // Then
        assertThat(authMethod, is(notNullValue()));
        assertThat(authMethod.getClass(), is(equalTo(FormBasedAuthenticationMethod.class)));
        FormBasedAuthenticationMethod method = (FormBasedAuthenticationMethod) authMethod;
        assertThat(method.getLoginRequestURL(), is(equalTo(TEST_URL_2)));
        assertThat(
                JobUtils.getPrivateField(method, AuthenticationData.PARAM_LOGIN_PAGE_URL),
                is(equalTo(TEST_URL_1)));
        assertThat(
                JobUtils.getPrivateField(method, AuthenticationData.PARAM_LOGIN_REQUEST_BODY),
                is(equalTo(TEST_FORM_DATA)));
    }

    @Test
    void shouldInitContextWithJsonAuth() {
        // Given
        Constant.messages = new I18N(Locale.ENGLISH);
        Context context = new Context(null, -1);

        AuthenticationData data = new AuthenticationData();
        data.setMethod("json");
        data.getParameters().put(AuthenticationData.PARAM_LOGIN_PAGE_URL, TEST_URL_1);
        data.getParameters().put(AuthenticationData.PARAM_LOGIN_REQUEST_URL, TEST_URL_2);
        data.getParameters().put(AuthenticationData.PARAM_LOGIN_REQUEST_BODY, TEST_JSON_DATA);

        AutomationProgress progress = new AutomationProgress();
        AutomationEnvironment env = new AutomationEnvironment(progress);

        // When
        data.initContextAuthentication(context, progress, env);
        AuthenticationMethod authMethod = context.getAuthenticationMethod();

        // Then
        assertThat(authMethod, is(notNullValue()));
        assertThat(authMethod.getClass(), is(equalTo(JsonBasedAuthenticationMethod.class)));
        JsonBasedAuthenticationMethod method = (JsonBasedAuthenticationMethod) authMethod;
        assertThat(method.getLoginRequestURL(), is(equalTo(TEST_URL_2)));
        assertThat(
                JobUtils.getPrivateField(method, AuthenticationData.PARAM_LOGIN_PAGE_URL),
                is(equalTo(TEST_URL_1)));
        assertThat(
                JobUtils.getPrivateField(method, AuthenticationData.PARAM_LOGIN_REQUEST_BODY),
                is(equalTo(TEST_JSON_DATA)));
    }

    @Test
    void shouldFailOnInvalidAuthData() {
        // Given
        AutomationProgress progress = new AutomationProgress();

        // When
        new AuthenticationData("bad data", progress);

        // Then
        assertThat(progress.hasErrors(), is(true));
        assertThat(progress.getErrors().size(), is(1));
        assertThat(progress.getErrors().get(0), is("!automation.error.env.badauth!"));
    }

    @Test
    void shouldFailOnInvalidAuthMethod() {
        // Given
        Constant.messages = new I18N(Locale.ENGLISH);
        AutomationProgress progress = new AutomationProgress();
        LinkedHashMap<String, Object> data = new LinkedHashMap<>();
        data.put("method", "badmethod");

        // When
        new AuthenticationData(data, progress);

        // Then
        assertThat(progress.hasErrors(), is(true));
        assertThat(progress.getErrors().size(), is(1));
        assertThat(progress.getErrors().get(0), is("!automation.error.env.auth.type.bad!"));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                AuthenticationData.PARAM_HOSTNAME,
                AuthenticationData.PARAM_REALM,
                AuthenticationData.PARAM_LOGIN_PAGE_URL,
                AuthenticationData.PARAM_LOGIN_REQUEST_BODY,
                AuthenticationData.PARAM_LOGIN_REQUEST_URL
            })
    void shouldFailOnBadStringParams(String param) {
        // Given
        Constant.messages = new I18N(Locale.ENGLISH);
        AutomationProgress progress = new AutomationProgress();
        LinkedHashMap<String, Object> data = new LinkedHashMap<>();
        LinkedHashMap<String, Object> params = new LinkedHashMap<>();
        params.put(param, new LinkedHashMap<String, Object>());
        data.put("parameters", params);

        // When
        new AuthenticationData(data, progress);

        // Then
        assertThat(progress.hasErrors(), is(true));
        assertThat(progress.getErrors().size(), is(1));
        assertThat(progress.getErrors().get(0), is("!automation.error.env.auth.field.bad!"));
    }

    @Test
    void shouldFailOnBadPortParam() {
        // Given
        Constant.messages = new I18N(Locale.ENGLISH);
        AutomationProgress progress = new AutomationProgress();
        LinkedHashMap<String, Object> data = new LinkedHashMap<>();
        LinkedHashMap<String, Object> params = new LinkedHashMap<>();
        params.put(AuthenticationData.PARAM_PORT, "not a num");
        data.put("parameters", params);

        // When
        new AuthenticationData(data, progress);

        // Then
        assertThat(progress.hasErrors(), is(true));
        assertThat(progress.getErrors().size(), is(1));
        assertThat(progress.getErrors().get(0), is("!automation.error.env.auth.field.bad!"));
    }
}
