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
package org.zaproxy.addon.exim.sites;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.zaproxy.addon.exim.ExtensionExim;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit test for {@link EximSiteNode}. */
class EximSiteNodeUnitTest extends TestUtils {
    private static Yaml yaml;

    @BeforeAll
    static void setup() {
        mockMessages(new ExtensionExim());
        yaml = new Yaml(new LoaderOptions());
    }

    @Test
    void shouldImportSimpleNode() {
        // Given
        String yamlStr =
                "- node: www.example.com\n"
                        + "  url: https://www.example.com\n"
                        + "  method: GET\n"
                        + "  responseLength: 1234\n"
                        + "  statusCode: 200\n";

        // When
        List<?> list = (ArrayList<?>) yaml.load(yamlStr);
        EximSiteNode node = new EximSiteNode((LinkedHashMap<?, ?>) list.get(0));

        // Then
        assertThat(node.getNode(), is(equalTo("www.example.com")));
        assertThat(node.getUrl(), is(equalTo("https://www.example.com")));
        assertThat(node.getMethod(), is(equalTo("GET")));
        assertThat(node.getResponseLength(), is(equalTo(1234)));
        assertThat(node.getStatusCode(), is(equalTo(200)));
        assertThat(node.getChildren().size(), is(equalTo(0)));
        assertThat(node.getErrors().size(), is(equalTo(0)));
    }

    @Test
    void shouldImportNodeHierarchy() {
        // Given
        String yamlStr =
                "- node: www.example.com\n"
                        + "  url: https://www.example.com\n"
                        + "  method: GET\n"
                        + "  responseLength: 1234\n"
                        + "  statusCode: 200\n"
                        + "  children:\n"
                        + "  - node: GET:/\n"
                        + "    url: https://www.example.com/\n"
                        + "    method: GET\n"
                        + "    responseLength: 2345\n"
                        + "    statusCode: 200\n"
                        + "  - node: GET:aaa\n"
                        + "    url: https://www.example.com/aaa\n"
                        + "    method: GET\n"
                        + "    responseLength: 3456\n"
                        + "    statusCode: 201\n"
                        + "    children:\n"
                        + "    - node: POST:bbb\n"
                        + "      url: https://www.example.com/aaa/bbb\n"
                        + "      method: POST\n"
                        + "      responseLength: 101\n"
                        + "      statusCode: 401\n";

        // When
        List<?> list = (ArrayList<?>) yaml.load(yamlStr);
        EximSiteNode node = new EximSiteNode((LinkedHashMap<?, ?>) list.get(0));

        // Then
        assertThat(node.getNode(), is(equalTo("www.example.com")));
        assertThat(node.getUrl(), is(equalTo("https://www.example.com")));
        assertThat(node.getMethod(), is(equalTo("GET")));
        assertThat(node.getResponseLength(), is(equalTo(1234)));
        assertThat(node.getStatusCode(), is(equalTo(200)));
        assertThat(node.getChildren().size(), is(equalTo(2)));

        EximSiteNode child1 = node.getChildren().get(0);
        assertThat(child1.getNode(), is(equalTo("GET:/")));
        assertThat(child1.getUrl(), is(equalTo("https://www.example.com/")));
        assertThat(child1.getMethod(), is(equalTo("GET")));
        assertThat(child1.getResponseLength(), is(equalTo(2345)));
        assertThat(child1.getStatusCode(), is(equalTo(200)));
        assertThat(child1.getChildren().size(), is(equalTo(0)));

        EximSiteNode child2 = node.getChildren().get(1);
        assertThat(child2.getNode(), is(equalTo("GET:aaa")));
        assertThat(child2.getUrl(), is(equalTo("https://www.example.com/aaa")));
        assertThat(child2.getMethod(), is(equalTo("GET")));
        assertThat(child2.getResponseLength(), is(equalTo(3456)));
        assertThat(child2.getStatusCode(), is(equalTo(201)));
        assertThat(child2.getChildren().size(), is(equalTo(1)));

        EximSiteNode child3 = child2.getChildren().get(0);
        assertThat(child3.getNode(), is(equalTo("POST:bbb")));
        assertThat(child3.getUrl(), is(equalTo("https://www.example.com/aaa/bbb")));
        assertThat(child3.getMethod(), is(equalTo("POST")));
        assertThat(child3.getResponseLength(), is(equalTo(101)));
        assertThat(child3.getStatusCode(), is(equalTo(401)));
        assertThat(child3.getChildren().size(), is(equalTo(0)));

        assertThat(node.getErrors().size(), is(equalTo(0)));
    }

    @Test
    void shouldReportErrorIfBadTypes() {
        // Given
        String yamlStr =
                "- node: www.example.com\n"
                        + "  url: https://www.example.com\n"
                        + "  method: true\n"
                        + "  responseLength: nan\n"
                        + "  statusCode: 200\n";

        // When
        List<?> list = (ArrayList<?>) yaml.load(yamlStr);
        EximSiteNode node = new EximSiteNode((LinkedHashMap<?, ?>) list.get(0));

        // Then
        assertThat(node.getNode(), is(equalTo("www.example.com")));
        assertThat(node.getUrl(), is(equalTo("https://www.example.com")));
        assertThat(node.getMethod(), is(equalTo(null)));
        assertThat(node.getResponseLength(), is(equalTo(-1)));
        assertThat(node.getStatusCode(), is(equalTo(200)));
        assertThat(node.getChildren().size(), is(equalTo(0)));
        assertThat(node.getErrors().size(), is(equalTo(2)));
        assertThat(
                node.getErrors().get(0),
                is(equalTo("Unexpected value type for key www.example.com: method")));
        assertThat(
                node.getErrors().get(1),
                is(equalTo("Unexpected value type for key www.example.com: responseLength")));
    }

    @Test
    void shouldReportErrorIfUnknownKeys() {
        // Given
        String yamlStr =
                "- node: www.example.com\n"
                        + "  url: https://www.example.com\n"
                        + "  method: GET\n"
                        + "  responseLength: 101\n"
                        + "  badKey1: true\n"
                        + "  badKey2: 666\n"
                        + "  statusCode: 200\n";

        LoaderOptions loadingConfig = new LoaderOptions();
        Yaml yaml = new Yaml(loadingConfig);

        // When
        List<?> list = (ArrayList<?>) yaml.load(yamlStr);
        EximSiteNode node = new EximSiteNode((LinkedHashMap<?, ?>) list.get(0));

        // Then
        assertThat(node.getNode(), is(equalTo("www.example.com")));
        assertThat(node.getUrl(), is(equalTo("https://www.example.com")));
        assertThat(node.getMethod(), is(equalTo("GET")));
        assertThat(node.getResponseLength(), is(equalTo(101)));
        assertThat(node.getStatusCode(), is(equalTo(200)));
        assertThat(node.getChildren().size(), is(equalTo(0)));
        assertThat(node.getErrors().size(), is(equalTo(2)));
        assertThat(
                node.getErrors().get(0),
                is(equalTo("Invalid key for node www.example.com: badKey1")));
        assertThat(
                node.getErrors().get(1),
                is(equalTo("Invalid key for node www.example.com: badKey2")));
    }
}
