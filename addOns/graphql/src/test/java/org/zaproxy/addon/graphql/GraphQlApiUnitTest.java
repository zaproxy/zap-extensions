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
package org.zaproxy.addon.graphql;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

import net.sf.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedConstruction;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit test for {@link GraphQlApi}. */
class GraphQlApiUnitTest extends TestUtils {

    private GraphQlApi api;

    @BeforeEach
    void prepare() {
        mockMessages(new ExtensionGraphQl());
        Model model = mock(Model.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
        Model.setSingletonForTesting(model);
        ExtensionLoader extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        ExtensionGraphQl extGraphQl =
                mock(ExtensionGraphQl.class, withSettings().strictness(Strictness.LENIENT));
        when(extGraphQl.getParam()).thenReturn(new GraphQlParam());
        given(extensionLoader.getExtension(ExtensionGraphQl.class)).willReturn(extGraphQl);
        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);
        api = new GraphQlApi();
    }

    @Test
    void shouldThrowApiExceptionIfMaxMessagesNegativeForUrl() {
        // Given
        JSONObject params = new JSONObject();
        params.put("endurl", "http://example.com/graphql");
        params.put("maxMessages", "-1");
        // When / Then
        ApiException exception =
                assertThrows(ApiException.class, () -> api.handleApiAction("importUrl", params));
        assertThat(exception.getType(), is(equalTo(ApiException.Type.ILLEGAL_PARAMETER)));
        assertThat(exception.toString(), containsString("(illegal_parameter): maxMessages"));
    }

    @Test
    void shouldThrowApiExceptionIfMaxMessagesNegativeForFile() {
        // Given
        JSONObject params = new JSONObject();
        params.put("endurl", "http://example.com/graphql");
        params.put("file", "/tmp/schema.graphql");
        params.put("maxMessages", "-1");
        // When / Then
        ApiException exception =
                assertThrows(ApiException.class, () -> api.handleApiAction("importFile", params));
        assertThat(exception.getType(), is(equalTo(ApiException.Type.ILLEGAL_PARAMETER)));
        assertThat(exception.toString(), containsString("(illegal_parameter): maxMessages"));
    }

    @Test
    void shouldPassMaxMessagesForUrl() throws Exception {
        // Given
        JSONObject params = new JSONObject();
        params.put("endurl", "http://example.com/graphql");
        params.put("url", "http://example.com/schema.graphql");
        params.put("maxMessages", "2");
        try (MockedConstruction<GraphQlParser> mocked = mockConstruction(GraphQlParser.class)) {
            // When
            api.handleApiAction("importUrl", params);
            // Then
            GraphQlParser parser = mocked.constructed().get(0);
            verify(parser).setMaxMessages(2);
            verify(parser).importUrl("http://example.com/schema.graphql");
        }
    }

    @Test
    void shouldPassMaxMessagesForFile() throws Exception {
        // Given
        JSONObject params = new JSONObject();
        params.put("endurl", "http://example.com/graphql");
        params.put("file", "/tmp/schema.graphql");
        params.put("maxMessages", "1");
        try (MockedConstruction<GraphQlParser> mocked = mockConstruction(GraphQlParser.class)) {
            // When
            api.handleApiAction("importFile", params);
            // Then
            GraphQlParser parser = mocked.constructed().get(0);
            verify(parser).setMaxMessages(1);
            verify(parser).importFile("/tmp/schema.graphql");
        }
    }
}
