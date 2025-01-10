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
package org.zaproxy.addon.oast;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.emptyString;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import net.sf.json.JSON;
import net.sf.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.OptionsParam;
import org.zaproxy.addon.oast.services.boast.BoastParam;
import org.zaproxy.addon.oast.services.boast.BoastService;
import org.zaproxy.addon.oast.services.callback.CallbackParam;
import org.zaproxy.addon.oast.services.callback.CallbackService;
import org.zaproxy.addon.oast.services.interactsh.InteractshParam;
import org.zaproxy.addon.oast.services.interactsh.InteractshService;
import org.zaproxy.zap.extension.api.API;
import org.zaproxy.zap.extension.api.API.RequestType;
import org.zaproxy.zap.extension.api.ApiElement;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.extension.api.ApiImplementor;
import org.zaproxy.zap.extension.api.ApiParameter;
import org.zaproxy.zap.extension.api.ApiResponse;
import org.zaproxy.zap.extension.api.ApiResponseElement;
import org.zaproxy.zap.extension.api.ApiResponseList;
import org.zaproxy.zap.extension.api.ApiResponseSet;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

class OastApiUnitTests extends TestUtils {

    private ExtensionOast ext;
    private OastApi api;
    private OastParam params;

    @BeforeEach
    void setUp() throws Exception {
        mockMessages(new ExtensionOast());

        ext = mock(ExtensionOast.class);
        params = new OastParam();
        params.load(new ZapXmlConfiguration());
        api = new OastApi(ext);
    }

    @Test
    void shouldHaveDescriptionsForAllApiElements() {
        List<String> missingKeys = new ArrayList<>();
        checkKey(api.getDescriptionKey(), missingKeys);
        checkApiElements(api, api.getApiActions(), API.RequestType.action, missingKeys);
        checkApiElements(api, api.getApiOthers(), API.RequestType.other, missingKeys);
        checkApiElements(api, api.getApiViews(), API.RequestType.view, missingKeys);

        assertThat(missingKeys, is(empty()));
    }

    private static void checkKey(String key, List<String> missingKeys) {
        if (!Constant.messages.containsKey(key)) {
            missingKeys.add(key);
        }
    }

    private static void checkApiElements(
            ApiImplementor api,
            List<? extends ApiElement> elements,
            RequestType type,
            List<String> missingKeys) {
        elements.sort((a, b) -> a.getName().compareTo(b.getName()));
        for (ApiElement element : elements) {
            assertThat(
                    "API " + type + " element: " + api.getPrefix() + "/" + element.getName(),
                    element.getDescriptionTag(),
                    is(not(emptyString())));
            checkKey(element.getDescriptionTag(), missingKeys);
            element.getParameters().stream()
                    .map(ApiParameter::getDescriptionKey)
                    .forEach(key -> checkKey(key, missingKeys));
        }
    }

    @Test
    void shouldGetDefaultActiveService() throws Exception {
        // Given / When
        ApiResponse res = api.handleApiView("getActiveScanService", new JSONObject());

        // Then
        assertThat(res instanceof ApiResponseElement, is(true));
        assertThat(((ApiResponseElement) res).getName(), is("getActiveScanService"));
        assertThat(((ApiResponseElement) res).getValue(), is(""));
    }

    @Test
    void shouldSetActiveService() throws Exception {
        // Given
        JSONObject apiParams = new JSONObject();
        apiParams.put("name", "BOAST");

        // When
        ApiResponse res = api.handleApiAction("setActiveScanService", apiParams);

        // Then
        assertThat(res instanceof ApiResponseElement, is(true));
        assertThat(((ApiResponseElement) res).getName(), is("Result"));
        assertThat(((ApiResponseElement) res).getValue(), is("OK"));
    }

    @Test
    void shouldGetDaysToKeepRecords() throws Exception {
        // Given / When
        given(ext.getParams()).willReturn(params);
        ApiResponse res = api.handleApiView("getDaysToKeepRecords", new JSONObject());

        // Then
        assertThat(res instanceof ApiResponseElement, is(true));
        assertThat(((ApiResponseElement) res).getName(), is("getDaysToKeepRecords"));
        assertThat(((ApiResponseElement) res).getValue(), is("45"));
    }

    @Test
    void shouldSetDaysToKeepRecords() throws Exception {
        // Given
        given(ext.getParams()).willReturn(params);
        JSONObject apiParams = new JSONObject();
        apiParams.put("days", "44");

        // When
        ApiResponse res = api.handleApiAction("setDaysToKeepRecords", apiParams);

        // Then
        assertThat(res instanceof ApiResponseElement, is(true));
        assertThat(((ApiResponseElement) res).getName(), is("Result"));
        assertThat(((ApiResponseElement) res).getValue(), is("OK"));
        assertThat(params.getDaysToKeepRecords(), is(44));
        verify(ext).trimDatabase(44);
    }

    @Test
    void shouldRejectInvalidActiveService() throws Exception {
        // Given
        doThrow(new IllegalArgumentException()).when(ext).setActiveScanOastService(anyString());
        JSONObject params = new JSONObject();
        params.put("name", "BAD");

        // When
        ApiException exception =
                assertThrows(
                        ApiException.class,
                        () -> {
                            api.handleApiAction("setActiveScanService", params);
                        });

        // Then
        assertThat(exception.getType(), is(ApiException.Type.ILLEGAL_PARAMETER));
        assertThat(exception.getMessage(), is("ILLEGAL_PARAMETER (BAD)"));
    }

    @Test
    void shouldGetServices() throws Exception {
        // Given
        Map<String, OastService> services = new HashMap<>();
        services.put("TEST", mock(OastService.class));
        given(ext.getOastServices()).willReturn(services);

        // When
        ApiResponse res = api.handleApiView("getServices", new JSONObject());

        // Then
        assertThat(res instanceof ApiResponseList, is(true));
        ApiResponseList resList = (ApiResponseList) res;
        assertThat(resList.getName(), is("getServices"));
        assertThat(resList.getItems().size(), is(1));
        assertThat(resList.getItems().get(0) instanceof ApiResponseElement, is(true));
        assertThat(((ApiResponseElement) resList.getItems().get(0)).getValue(), is("TEST"));
    }

    @Test
    void shouldGetBoastOptions() throws Exception {
        // Given
        BoastService service = mock(BoastService.class);
        BoastParam bparams = new BoastParam();
        bparams.load(new ZapXmlConfiguration());
        bparams.setBoastUri("https://www.example.com/");
        given(service.getParam()).willReturn(bparams);
        given(ext.getBoastService()).willReturn(service);

        // When
        ApiResponse res = api.handleApiView("getBoastOptions", new JSONObject());
        JSON json = res.toJSON();

        // Then
        assertThat(res instanceof ApiResponseSet, is(true));
        assertThat(json instanceof JSONObject, is(true));
        JSONObject jobj = (JSONObject) json;
        assertThat(jobj.size(), is(2));
        assertThat(jobj.get("server"), is("https://www.example.com/"));
        assertThat(jobj.get("pollInSecs"), is("60"));
    }

    @Test
    void shouldSetBoastOptions() throws Exception {
        // Given
        Model model = mock(Model.class);
        given(model.getOptionsParam()).willReturn(mock(OptionsParam.class));
        given(ext.getModel()).willReturn(model);
        BoastService service = mock(BoastService.class);
        BoastParam bparams = new BoastParam();
        bparams.load(new ZapXmlConfiguration());
        given(service.getParam()).willReturn(bparams);
        given(ext.getBoastService()).willReturn(service);
        JSONObject apiParams = new JSONObject();
        apiParams.put("server", "https://www.example.com/test");
        apiParams.put("pollInSecs", "59");

        // When
        ApiResponse res = api.handleApiAction("setBoastOptions", apiParams);

        // Then
        assertThat(res instanceof ApiResponseElement, is(true));
        assertThat(((ApiResponseElement) res).getName(), is("Result"));
        assertThat(((ApiResponseElement) res).getValue(), is("OK"));
        assertThat(bparams.getBoastUri(), is("https://www.example.com/test"));
        assertThat(bparams.getPollingFrequency(), is(59));
    }

    @Test
    void shouldGetCallbackOptions() throws Exception {
        // Given
        CallbackService service = mock(CallbackService.class);
        CallbackParam bparams = new CallbackParam();
        bparams.load(new ZapXmlConfiguration());
        bparams.setLocalAddress("https://www.example.com/loc");
        bparams.setRemoteAddress("https://www.example.com/rem");
        given(service.getParam()).willReturn(bparams);
        given(ext.getCallbackService()).willReturn(service);

        // When
        ApiResponse res = api.handleApiView("getCallbackOptions", new JSONObject());
        JSON json = res.toJSON();

        // Then
        assertThat(res instanceof ApiResponseSet, is(true));
        assertThat(json instanceof JSONObject, is(true));
        JSONObject jobj = (JSONObject) json;
        assertThat(jobj.size(), is(3));
        assertThat(jobj.get("localAddress"), is("https://www.example.com/loc"));
        assertThat(jobj.get("remoteAddress"), is("https://www.example.com/rem"));
        // What else?
    }

    @Test
    void shouldSetCallbackOptions() throws Exception {
        // Given
        Model model = mock(Model.class);
        given(model.getOptionsParam()).willReturn(mock(OptionsParam.class));
        given(ext.getModel()).willReturn(model);
        CallbackService service = mock(CallbackService.class);
        CallbackParam bparams = new CallbackParam();
        bparams.load(new ZapXmlConfiguration());
        given(service.getParam()).willReturn(bparams);
        given(ext.getCallbackService()).willReturn(service);
        JSONObject apiParams = new JSONObject();
        apiParams.put("localAddress", "https://www.example.com/loc");
        apiParams.put("remoteAddress", "https://www.example.com/rem");
        apiParams.put("port", "1234");

        // When
        ApiResponse res = api.handleApiAction("setCallbackOptions", apiParams);

        // Then
        assertThat(res instanceof ApiResponseElement, is(true));
        assertThat(((ApiResponseElement) res).getName(), is("Result"));
        assertThat(((ApiResponseElement) res).getValue(), is("OK"));
        assertThat(bparams.getLocalAddress(), is("https://www.example.com/loc"));
        assertThat(bparams.getRemoteAddress(), is("https://www.example.com/rem"));
        assertThat(bparams.getPort(), is(1234));
    }

    @Test
    void shouldGetInteractshOptions() throws Exception {
        // Given
        InteractshService service = mock(InteractshService.class);
        InteractshParam iparams = new InteractshParam();
        iparams.load(new ZapXmlConfiguration());
        iparams.setServerUrl("https://www.example.com/");
        iparams.setAuthToken("abcde");
        given(service.getParam()).willReturn(iparams);
        given(ext.getInteractshService()).willReturn(service);

        // When
        ApiResponse res = api.handleApiView("getInteractshOptions", new JSONObject());
        JSON json = res.toJSON();

        // Then
        assertThat(res instanceof ApiResponseSet, is(true));
        assertThat(json instanceof JSONObject, is(true));
        JSONObject jobj = (JSONObject) json;
        assertThat(jobj.size(), is(3));
        assertThat(jobj.get("server"), is("https://www.example.com/"));
        assertThat(jobj.get("pollInSecs"), is("60"));
        assertThat(jobj.get("authToken"), is("abcde"));
    }

    @Test
    void shouldSetInteractshOptions() throws Exception {
        // Given
        Model model = mock(Model.class);
        given(model.getOptionsParam()).willReturn(mock(OptionsParam.class));
        given(ext.getModel()).willReturn(model);
        InteractshService service = mock(InteractshService.class);
        InteractshParam bparams = new InteractshParam();
        bparams.load(new ZapXmlConfiguration());
        given(service.getParam()).willReturn(bparams);
        given(ext.getInteractshService()).willReturn(service);
        JSONObject apiParams = new JSONObject();
        apiParams.put("server", "https://www.example.com/test");
        apiParams.put("pollInSecs", "59");
        apiParams.put("authToken", "abcde");

        // When
        ApiResponse res = api.handleApiAction("setInteractshOptions", apiParams);

        // Then
        assertThat(res instanceof ApiResponseElement, is(true));
        assertThat(((ApiResponseElement) res).getName(), is("Result"));
        assertThat(((ApiResponseElement) res).getValue(), is("OK"));
        assertThat(bparams.getServerUrl(), is("https://www.example.com/test"));
        assertThat(bparams.getPollingFrequency(), is(59));
        assertThat(bparams.getAuthToken(), is("abcde"));
    }
}
