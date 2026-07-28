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
package org.zaproxy.addon.llmlocal;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.is;

import java.util.List;
import org.junit.jupiter.api.Test;

class JlamaHuggingFaceCatalogUnitTest {

    @Test
    void shouldParseAndPreferJlamaModels() throws Exception {
        String json =
                """
                [
                  {"id":"tjake/other-model"},
                  {"modelId":"tjake/TinyLlama-1.1B-Chat-v1.0-Jlama-Q4"},
                  {"id":"tjake/Llama-3.2-1B-Instruct-JQ4"}
                ]
                """;

        List<String> ids = JlamaHuggingFaceCatalog.parseModelIds(json);

        assertThat(ids.get(0), is("tjake/Llama-3.2-1B-Instruct-JQ4"));
        assertThat(ids, hasItem("tjake/TinyLlama-1.1B-Chat-v1.0-Jlama-Q4"));
        assertThat(ids.get(ids.size() - 1), is("tjake/other-model"));
        assertThat(JlamaHuggingFaceCatalog.isPreferredJlamaModel("tjake/x-Jlama-Q4"), is(true));
        assertThat(JlamaHuggingFaceCatalog.isPreferredJlamaModel("tjake/plain"), is(false));
    }

    @Test
    void shouldPreserveAllIds() throws Exception {
        String json =
                """
                [
                  {"id":"tjake/a-Jlama"},
                  {"id":"tjake/b-JQ4"}
                ]
                """;

        assertThat(
                JlamaHuggingFaceCatalog.parseModelIds(json),
                contains("tjake/a-Jlama", "tjake/b-JQ4"));
    }
}
