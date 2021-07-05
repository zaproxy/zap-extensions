/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
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
package org.zaproxy.zap.extension.openapi;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import java.util.Arrays;
import java.util.HashMap;
import java.util.stream.Collectors;
import net.sf.json.JSONObject;
import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.model.Model;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.model.DefaultNameValuePair;
import org.zaproxy.zap.model.NameValuePair;

/** Unit test for {@link OpenApiAPI}. */
class OpenApiAPIUnitTest extends AbstractServerTest {

    private ExtensionOpenApi extension;

    private OpenApiAPI openApiAPI;

    @BeforeEach
    void prepare() {
        extension = mock(ExtensionOpenApi.class);
        openApiAPI = new OpenApiAPI(extension);
        Model model = mock(Model.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
        Model.setSingletonForTesting(model);
    }

    @Test
    void shouldThrowBadActionIfActionUnknown() {
        // Given
        String actionName = "_NotKnownAction_";
        // When / Then
        ApiException exception =
                assertThrows(
                        ApiException.class, () -> openApiAPI.handleApiAction(actionName, params()));
        assertThat(exception.getType(), is(equalTo(ApiException.Type.BAD_ACTION)));
    }

    @Nested
    class ApiImportUrl {

        private static final String ACTION = "importUrl";

        @Test
        void shouldThrowIllegalParameterIfFailedToAccessTarget() {
            // Given
            JSONObject params = params(param("url", "http://not-reachable.example.com"));
            given(extension.importOpenApiDefinition(any(URI.class), eq(""), eq(false), eq(-1)))
                    .willReturn(null);
            // When / Then
            ApiException exception =
                    assertThrows(
                            ApiException.class, () -> openApiAPI.handleApiAction(ACTION, params));
            assertThat(exception.getType(), is(equalTo(ApiException.Type.ILLEGAL_PARAMETER)));
            assertThat(exception.toString(), containsString("Failed to access the target."));
        }
    }

    private static JSONObject params(NameValuePair... params) {
        if (params == null || params.length == 0) {
            return JSONObject.fromObject(new HashMap<>());
        }

        return JSONObject.fromObject(
                Arrays.asList(params).stream()
                        .collect(
                                Collectors.toMap(NameValuePair::getName, NameValuePair::getValue)));
    }

    private static NameValuePair param(String name, String value) {
        return new DefaultNameValuePair(name, value);
    }
}
