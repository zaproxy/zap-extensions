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
package org.zaproxy.addon.client.ajax;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.emptyString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.withSettings;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import net.sf.json.JSONObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.client.ExtensionClientIntegration;
import org.zaproxy.zap.extension.api.API;
import org.zaproxy.zap.extension.api.API.RequestType;
import org.zaproxy.zap.extension.api.ApiElement;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.extension.api.ApiImplementor;
import org.zaproxy.zap.extension.api.ApiParameter;
import org.zaproxy.zap.extension.api.ApiResponse;
import org.zaproxy.zap.extension.api.ApiResponseElement;
import org.zaproxy.zap.extension.api.ApiResponseList;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit test for {@link AjaxSpiderAPI}. */
class AjaxSpiderAPIUnitTest extends TestUtils {

    private static final String SCAN_URL = "http://example.com";

    private AjaxSpiderAPI ajaxSpiderAPI;
    private ApiImplementor clientSpiderApi;
    private MockedStatic<API> apiStatic;

    @BeforeEach
    void setUp() {
        mockMessages(new ExtensionClientIntegration());

        clientSpiderApi = mock(ApiImplementor.class, withSettings().strictness(Strictness.LENIENT));
        API api = mock(API.class, withSettings().strictness(Strictness.LENIENT));
        given(api.getImplementors()).willReturn(Map.of("clientSpider", clientSpiderApi));

        apiStatic = mockStatic(API.class);
        apiStatic.when(API::getInstance).thenReturn(api);

        ajaxSpiderAPI = new AjaxSpiderAPI();
    }

    @AfterEach
    void tearDown() {
        apiStatic.close();
        Constant.messages = null;
    }

    private void givenScanStarted() throws ApiException {
        given(clientSpiderApi.handleApiAction(eq("scan"), any()))
                .willReturn(new ApiResponseElement("scan", "1"));
        JSONObject params = new JSONObject();
        params.put("url", SCAN_URL);
        ajaxSpiderAPI.handleApiAction("scan", params);
    }

    @Test
    void shouldHavePrefix() {
        // Given / When
        String prefix = ajaxSpiderAPI.getPrefix();
        // Then
        assertThat(prefix, is(equalTo("ajaxSpider")));
    }

    @Test
    void shouldAddApiElements() {
        // Given / When / Then
        assertThat(ajaxSpiderAPI.getApiActions(), hasSize(22));
        assertThat(ajaxSpiderAPI.getApiViews(), hasSize(19));
        assertThat(ajaxSpiderAPI.getApiOthers(), hasSize(0));
    }

    @ParameterizedTest
    @EmptySource
    @ValueSource(strings = {"unknown", "something"})
    void shouldThrowApiExceptionForUnknownAction(String name) {
        // Given
        JSONObject params = new JSONObject();
        // When
        ApiException exception =
                assertThrows(ApiException.class, () -> ajaxSpiderAPI.handleApiAction(name, params));
        // Then
        assertThat(exception.getType(), is(equalTo(ApiException.Type.BAD_ACTION)));
    }

    @ParameterizedTest
    @EmptySource
    @ValueSource(strings = {"unknown", "something"})
    void shouldThrowApiExceptionForUnknownView(String name) {
        // Given
        JSONObject params = new JSONObject();
        // When
        ApiException exception =
                assertThrows(ApiException.class, () -> ajaxSpiderAPI.handleApiView(name, params));
        // Then
        assertThat(exception.getType(), is(equalTo(ApiException.Type.BAD_VIEW)));
    }

    @Test
    void shouldHaveDescriptionsForAllApiElements() {
        List<String> missingKeys = new ArrayList<>();
        List<String> missingDescriptions = new ArrayList<>();
        checkApiElements(
                ajaxSpiderAPI,
                ajaxSpiderAPI.getApiActions(),
                API.RequestType.action,
                missingKeys,
                missingDescriptions);
        checkApiElements(
                ajaxSpiderAPI,
                ajaxSpiderAPI.getApiViews(),
                API.RequestType.view,
                missingKeys,
                missingDescriptions);
        assertThat(missingKeys, is(empty()));
        assertThat(missingDescriptions, is(empty()));
    }

    @Test
    void shouldDelegateScanToClientSpiderWithoutScopeCheckByDefault() throws Exception {
        // Given
        given(clientSpiderApi.handleApiAction(eq("scan"), any()))
                .willReturn(new ApiResponseElement("scan", "1"));
        JSONObject params = new JSONObject();
        params.put("url", SCAN_URL);

        // When
        ajaxSpiderAPI.handleApiAction("scan", params);

        // Then
        ArgumentCaptor<JSONObject> captor = ArgumentCaptor.forClass(JSONObject.class);
        verify(clientSpiderApi).handleApiAction(eq("scan"), captor.capture());
        assertThat(captor.getValue().getString("url"), is(equalTo(SCAN_URL)));
        assertThat(captor.getValue().containsKey("scopeCheck"), is(false));
        assertThat(captor.getValue().containsKey("inScope"), is(false));
    }

    @Test
    void shouldMapInScopeToStrictScopeCheck() throws Exception {
        // Given
        given(clientSpiderApi.handleApiAction(eq("scan"), any()))
                .willReturn(new ApiResponseElement("scan", "1"));
        JSONObject params = new JSONObject();
        params.put("url", SCAN_URL);
        params.put("inScope", true);

        // When
        ajaxSpiderAPI.handleApiAction("scan", params);

        // Then
        ArgumentCaptor<JSONObject> captor = ArgumentCaptor.forClass(JSONObject.class);
        verify(clientSpiderApi).handleApiAction(eq("scan"), captor.capture());
        assertThat(captor.getValue().getString("scopeCheck"), is(equalTo("STRICT")));
    }

    @Test
    void shouldDelegateScanAsUserToClientSpiderScanForwardingUserAndContext() throws Exception {
        // Given
        given(clientSpiderApi.handleApiAction(eq("scan"), any()))
                .willReturn(new ApiResponseElement("scan", "1"));
        JSONObject params = new JSONObject();
        params.put("contextName", "testContext");
        params.put("userName", "testUser");
        params.put("inScope", true);

        // When
        ajaxSpiderAPI.handleApiAction("scanAsUser", params);

        // Then
        ArgumentCaptor<JSONObject> captor = ArgumentCaptor.forClass(JSONObject.class);
        verify(clientSpiderApi).handleApiAction(eq("scan"), captor.capture());
        assertThat(captor.getValue().getString("contextName"), is(equalTo("testContext")));
        assertThat(captor.getValue().getString("userName"), is(equalTo("testUser")));
        assertThat(captor.getValue().getString("scopeCheck"), is(equalTo("STRICT")));
    }

    @Test
    void shouldThrowScanInProgressWhenScanAlreadyRunning() throws Exception {
        // Given
        givenScanStarted();
        given(clientSpiderApi.handleApiView(eq("status"), any()))
                .willReturn(new ApiResponseElement("status", "50"));
        JSONObject params = new JSONObject();
        params.put("url", SCAN_URL);

        // When
        ApiException exception =
                assertThrows(
                        ApiException.class, () -> ajaxSpiderAPI.handleApiAction("scan", params));

        // Then
        assertThat(exception.getType(), is(equalTo(ApiException.Type.SCAN_IN_PROGRESS)));
    }

    @Test
    void shouldNotThrowScanInProgressWhenPreviousScanFinished() throws Exception {
        // Given
        givenScanStarted();
        given(clientSpiderApi.handleApiView(eq("status"), any()))
                .willReturn(new ApiResponseElement("status", "100"));
        given(clientSpiderApi.handleApiAction(eq("scan"), any()))
                .willReturn(new ApiResponseElement("scan", "2"));
        JSONObject params = new JSONObject();
        params.put("url", SCAN_URL);

        // When / Then
        assertThat(
                ajaxSpiderAPI.handleApiAction("scan", params), is(equalTo(ApiResponseElement.OK)));
    }

    @Test
    void shouldDelegateStopToClientSpiderWithTrackedScanId() throws Exception {
        // Given
        givenScanStarted();

        // When
        ajaxSpiderAPI.handleApiAction("stop", new JSONObject());

        // Then
        ArgumentCaptor<JSONObject> captor = ArgumentCaptor.forClass(JSONObject.class);
        verify(clientSpiderApi).handleApiAction(eq("stop"), captor.capture());
        assertThat(captor.getValue().getInt("scanId"), is(equalTo(1)));
    }

    @Test
    void shouldNotCallClientSpiderStopWhenNoScanStarted() throws Exception {
        // Given / When
        ajaxSpiderAPI.handleApiAction("stop", new JSONObject());

        // Then
        verify(clientSpiderApi, never()).handleApiAction(eq("stop"), any());
    }

    @Test
    void shouldReportRunningStatusFromClientSpider() throws Exception {
        // Given
        givenScanStarted();
        given(clientSpiderApi.handleApiView(eq("status"), any()))
                .willReturn(new ApiResponseElement("status", "50"));

        // When
        String status =
                ((ApiResponseElement) ajaxSpiderAPI.handleApiView("status", new JSONObject()))
                        .getValue();

        // Then
        assertThat(status, is(equalTo("running")));
    }

    @Test
    void shouldReportStoppedStatusWhenClientSpiderProgressIsComplete() throws Exception {
        // Given
        givenScanStarted();
        given(clientSpiderApi.handleApiView(eq("status"), any()))
                .willReturn(new ApiResponseElement("status", "100"));

        // When
        String status =
                ((ApiResponseElement) ajaxSpiderAPI.handleApiView("status", new JSONObject()))
                        .getValue();

        // Then
        assertThat(status, is(equalTo("stopped")));
    }

    @Test
    void shouldReportStoppedStatusBeforeAnyScanWithoutCallingClientSpider() throws Exception {
        // Given / When
        String status =
                ((ApiResponseElement) ajaxSpiderAPI.handleApiView("status", new JSONObject()))
                        .getValue();

        // Then
        assertThat(status, is(equalTo("stopped")));
        verify(clientSpiderApi, never()).handleApiView(any(), any());
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "addAllowedResource",
                "addExcludedElement",
                "modifyExcludedElement",
                "removeAllowedResource",
                "removeExcludedElement",
                "setEnabledAllowedResource"
            })
    void shouldNoOpAjaxSpiderOnlyActions(String name) throws Exception {
        // Given
        JSONObject params = new JSONObject();
        params.put("regex", "test");
        params.put("enabled", true);
        params.put("contextName", "testContext");
        params.put("description", "testDescription");
        params.put("element", "a");

        // When
        ApiResponseElement response =
                (ApiResponseElement) ajaxSpiderAPI.handleApiAction(name, params);

        // Then
        assertThat(response, is(equalTo(ApiResponseElement.OK)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"allowedResources", "excludedElements", "results"})
    void shouldReturnEmptyListForAjaxSpiderOnlyViews(String name) throws Exception {
        // Given / When
        ApiResponseList response =
                (ApiResponseList) ajaxSpiderAPI.handleApiView(name, new JSONObject());

        // Then
        assertThat(response.getItems(), is(empty()));
    }

    @Test
    void shouldReturnEmptyInScopeOutOfScopeErrorsObjectForFullResultsView() throws Exception {
        // Given / When
        ApiResponse response = ajaxSpiderAPI.handleApiView("fullResults", new JSONObject());
        JSONObject json = ((JSONObject) response.toJSON()).getJSONObject("fullResults");

        // Then
        assertThat(json.getJSONArray("inScope").size(), is(equalTo(0)));
        assertThat(json.getJSONArray("outOfScope").size(), is(equalTo(0)));
        assertThat(json.getJSONArray("errors").size(), is(equalTo(0)));
    }

    @Test
    void shouldReturnZeroForNumberOfResultsView() throws Exception {
        // Given / When
        String value =
                ((ApiResponseElement)
                                ajaxSpiderAPI.handleApiView("numberOfResults", new JSONObject()))
                        .getValue();

        // Then
        assertThat(value, is(equalTo("0")));
    }

    @Test
    void shouldDelegateSetOptionMaxCrawlDepthToClientSpiderMaxDepth() throws Exception {
        // Given
        given(clientSpiderApi.handleApiOptionAction(eq("setOptionMaxDepth"), any()))
                .willReturn(ApiResponseElement.OK);
        JSONObject params = new JSONObject();
        params.put("Integer", 8);

        // When
        ApiResponse response = ajaxSpiderAPI.handleApiAction("setOptionMaxCrawlDepth", params);

        // Then
        assertThat(response, is(equalTo(ApiResponseElement.OK)));
        ArgumentCaptor<JSONObject> captor = ArgumentCaptor.forClass(JSONObject.class);
        verify(clientSpiderApi).handleApiOptionAction(eq("setOptionMaxDepth"), captor.capture());
        assertThat(captor.getValue().getInt("Integer"), is(equalTo(8)));
    }

    @Test
    void shouldDelegateGetOptionMaxCrawlDepthToClientSpiderMaxDepth() throws Exception {
        // Given
        given(clientSpiderApi.handleApiOptionView(eq("optionMaxDepth"), any()))
                .willReturn(new ApiResponseElement("optionMaxDepth", "9"));

        // When
        ApiResponseElement response =
                (ApiResponseElement)
                        ajaxSpiderAPI.handleApiView("optionMaxCrawlDepth", new JSONObject());

        // Then
        assertThat(response.getName(), is(equalTo("optionMaxCrawlDepth")));
        assertThat(response.getValue(), is(equalTo("9")));
    }

    @Test
    void shouldDelegateSetOptionNumberOfBrowsersToClientSpiderThreadCount() throws Exception {
        // Given
        given(clientSpiderApi.handleApiOptionAction(eq("setOptionThreadCount"), any()))
                .willReturn(ApiResponseElement.OK);
        JSONObject params = new JSONObject();
        params.put("Integer", 4);

        // When
        ajaxSpiderAPI.handleApiAction("setOptionNumberOfBrowsers", params);

        // Then
        ArgumentCaptor<JSONObject> captor = ArgumentCaptor.forClass(JSONObject.class);
        verify(clientSpiderApi).handleApiOptionAction(eq("setOptionThreadCount"), captor.capture());
        assertThat(captor.getValue().getInt("Integer"), is(equalTo(4)));
    }

    @Test
    void shouldNoOpAjaxSpiderOnlyOptionButRoundTripValue() throws Exception {
        // Given
        JSONObject setParams = new JSONObject();
        setParams.put("Integer", 42);

        // When
        ajaxSpiderAPI.handleApiAction("setOptionMaxCrawlStates", setParams);
        String value =
                ((ApiResponseElement)
                                ajaxSpiderAPI.handleApiView(
                                        "optionMaxCrawlStates", new JSONObject()))
                        .getValue();

        // Then
        assertThat(value, is(equalTo("42")));
    }

    private static void checkKey(String key, List<String> missingKeys, List<String> missingDescs) {
        if (!Constant.messages.containsKey(key)) {
            missingKeys.add(key);
        } else if (Constant.messages.getString(key).isBlank()) {
            missingDescs.add(key);
        }
    }

    private static void checkApiElements(
            ApiImplementor api,
            List<? extends ApiElement> elements,
            RequestType type,
            List<String> missingKeys,
            List<String> missingDescriptions) {
        elements.sort((a, b) -> a.getName().compareTo(b.getName()));
        for (ApiElement element : elements) {
            assertThat(
                    "API " + type + " element: " + api.getPrefix() + "/" + element.getName(),
                    element.getDescriptionTag(),
                    is(not(emptyString())));
            checkKey(element.getDescriptionTag(), missingKeys, missingDescriptions);
            element.getParameters().stream()
                    .map(ApiParameter::getDescriptionKey)
                    .forEach(key -> checkKey(key, missingKeys, missingDescriptions));
        }
    }
}
