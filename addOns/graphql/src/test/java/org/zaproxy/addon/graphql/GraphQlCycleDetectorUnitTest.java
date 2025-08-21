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
package org.zaproxy.addon.graphql;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import graphql.schema.GraphQLSchema;
import graphql.schema.idl.SchemaParser;
import graphql.schema.idl.UnExecutableSchemaGenerator;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.commonlib.ValueProvider;
import org.zaproxy.addon.graphql.GraphQlCycleDetector.GraphQlCycleDetectionResult;
import org.zaproxy.zap.extension.alert.ExtensionAlert;
import org.zaproxy.zap.network.HttpRequestBody;
import org.zaproxy.zap.testutils.TestUtils;

class GraphQlCycleDetectorUnitTest extends TestUtils {
    GraphQlParam param;
    private ValueProvider valueProvider;

    @BeforeEach
    void setup() throws Exception {
        setUpZap();
        param =
                new GraphQlParam(
                        true,
                        5,
                        true,
                        5,
                        5,
                        true,
                        null,
                        null,
                        GraphQlParam.RequestMethodOption.POST_JSON,
                        GraphQlParam.CycleDetectionModeOption.EXHAUSTIVE,
                        100);
        valueProvider = mock(ValueProvider.class);
    }

    @Test
    void shouldDetectCycles() {
        // Given
        String sdl = getHtml("circularRelationship.graphql");
        GraphQLSchema schema =
                UnExecutableSchemaGenerator.makeUnExecutableSchema(new SchemaParser().parse(sdl));
        var generator = new GraphQlGenerator(valueProvider, schema, null, param);
        var cyclesDetector = new GraphQlCycleDetector(schema, generator, null, param);
        List<GraphQlCycleDetectionResult> results = new ArrayList<>();
        // When
        cyclesDetector.detectCycles(results::add);
        // Then
        assertThat(
                results,
                is(
                        equalTo(
                                List.of(
                                        new GraphQlCycleDetectionResult(
                                                "Query -> (Thread -> Message -> Thread)",
                                                "query { thread { message { thread { id } } } }",
                                                "{}")))));
    }

    @Test
    void shouldRaiseAlertsForDetectedCycles() throws Exception {
        // Given
        ExtensionLoader extensionLoader = mock(ExtensionLoader.class);
        Control.initSingletonForTesting(mock(Model.class), extensionLoader);
        ExtensionAlert extAlert = mock(ExtensionAlert.class);
        when(extensionLoader.getExtension(ExtensionAlert.class)).thenReturn(extAlert);
        String sdl = getHtml("circularRelationship.graphql");
        GraphQLSchema schema =
                UnExecutableSchemaGenerator.makeUnExecutableSchema(new SchemaParser().parse(sdl));
        var generator = new GraphQlGenerator(valueProvider, schema, null, param);
        var queryMsgBuilder =
                new GraphQlQueryMessageBuilder(UrlBuilder.build("https://example.com/graphql"));
        var cyclesDetector = new GraphQlCycleDetector(schema, generator, queryMsgBuilder, param);
        // When
        cyclesDetector.detectCycles();
        // Then
        ArgumentCaptor<Alert> alertCaptor = ArgumentCaptor.forClass(Alert.class);
        verify(extAlert).alertFound(alertCaptor.capture(), isNull());
        assertThat(
                alertCaptor.getValue(),
                is(
                        equalTo(
                                Alert.builder()
                                        .setPluginId(50007)
                                        .setAlertRef("50007-3")
                                        .setName("!graphql.cycles.alert.name!")
                                        .setDescription("!graphql.cycles.alert.desc!")
                                        .setReference("!graphql.cycles.alert.ref!")
                                        .setSolution("!graphql.cycles.alert.soln!")
                                        .setConfidence(Alert.CONFIDENCE_HIGH)
                                        .setRisk(Alert.RISK_INFO)
                                        .setCweId(16)
                                        .setWascId(15)
                                        .setSource(Alert.Source.TOOL)
                                        .setTags(
                                                Map.of(
                                                        "OWASP_2023_API4",
                                                        "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
                                                        "OWASP_2021_A04",
                                                        "https://owasp.org/Top10/A04_2021-Insecure_Design/",
                                                        "WSTG-v42-APIT-01",
                                                        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL",
                                                        "CWE-16",
                                                        "https://cwe.mitre.org/data/definitions/16.html"))
                                        .setOtherInfo("Query -> (Thread -> Message -> Thread)")
                                        .setMessage(
                                                new HttpMessage(
                                                        new HttpRequestHeader(
                                                                """
                                                                    POST https://example.com/graphql HTTP/1.1
                                                                    host: example.com
                                                                    user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36
                                                                    pragma: no-cache
                                                                    cache-control: no-cache
                                                                    content-type: application/json
                                                                    Accept: application/json
                                                                    content-length: 73
                                                                    """),
                                                        new HttpRequestBody(
                                                                "{\"query\":\"query { thread { message { thread { id } } } }\",\"variables\":{}}")))
                                        .build())));
    }
}
