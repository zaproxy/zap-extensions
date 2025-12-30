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
package org.zaproxy.zap.extension.llmheader;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;

import java.util.List;
import org.junit.jupiter.api.Test;

class LLMResultParserTest {

    @Test
    void shouldParseValidJson() {
        // Given
        String json =
                "[{\"issue\": \"Test Issue\", \"severity\": \"High\", \"confidence\": \"Medium\", \"recommendation\": \"Fix it\"}]";

        // When
        List<LLMIssue> issues = LLMResultParser.parse(json);

        // Then
        assertThat(issues, hasSize(1));
        assertThat(issues.get(0).getIssue(), is("Test Issue"));
        assertThat(issues.get(0).getSeverity(), is("High"));
    }

    @Test
    void shouldParseJsonWithMarkdown() {
        // Given
        String json = "```json\n[{\"issue\": \"Test Issue\"}]\n```";

        // When
        List<LLMIssue> issues = LLMResultParser.parse(json);

        // Then
        assertThat(issues, hasSize(1));
        assertThat(issues.get(0).getIssue(), is("Test Issue"));
    }
}
