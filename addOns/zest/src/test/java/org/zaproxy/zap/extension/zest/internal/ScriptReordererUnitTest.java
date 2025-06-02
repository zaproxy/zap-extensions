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
package org.zaproxy.zap.extension.zest.internal;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.ArrayList;
import java.util.List;
import net.sf.json.JSONException;
import net.sf.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zaproxy.zest.core.v1.ZestComment;
import org.zaproxy.zest.core.v1.ZestStatement;

class ScriptReordererUnitTest {

    private ScriptReorderer reorderer;
    private List<ZestStatement> processedStatements;

    @BeforeEach
    void setup() {
        processedStatements = new ArrayList<>();
        reorderer = new ScriptReorderer(processedStatements::add);
    }

    @Test
    void shouldHandleStatementsInRightOrder() throws Exception {
        // Given / When
        reorderer.recordStatement(createJsonStatement(1));
        reorderer.recordStatement(createJsonStatement(2));
        reorderer.recordStatement(createJsonStatement(3));
        reorderer.recordStatement(createJsonStatement(4));

        // Then
        assertThat(processedStatements.size(), is(equalTo(4)));
        assertThat(((ZestComment) processedStatements.get(0)).getComment(), is(equalTo("Index 1")));
        assertThat(((ZestComment) processedStatements.get(1)).getComment(), is(equalTo("Index 2")));
        assertThat(((ZestComment) processedStatements.get(2)).getComment(), is(equalTo("Index 3")));
        assertThat(((ZestComment) processedStatements.get(3)).getComment(), is(equalTo("Index 4")));
    }

    @Test
    void shouldHandleStatementsInReverseOrder() throws Exception {
        // Given / When
        reorderer.recordStatement(createJsonStatement(4));
        reorderer.recordStatement(createJsonStatement(3));
        reorderer.recordStatement(createJsonStatement(2));
        reorderer.recordStatement(createJsonStatement(1));

        // Then
        assertThat(processedStatements.size(), is(equalTo(4)));
        assertThat(((ZestComment) processedStatements.get(0)).getComment(), is(equalTo("Index 1")));
        assertThat(((ZestComment) processedStatements.get(1)).getComment(), is(equalTo("Index 2")));
        assertThat(((ZestComment) processedStatements.get(2)).getComment(), is(equalTo("Index 3")));
        assertThat(((ZestComment) processedStatements.get(3)).getComment(), is(equalTo("Index 4")));
    }

    @Test
    void shouldHandleStatementsInRandomOrder() throws Exception {
        // Given / When
        reorderer.recordStatement(createJsonStatement(2));
        reorderer.recordStatement(createJsonStatement(4));
        reorderer.recordStatement(createJsonStatement(3));
        reorderer.recordStatement(createJsonStatement(1));

        // Then
        assertThat(processedStatements.size(), is(equalTo(4)));
        assertThat(((ZestComment) processedStatements.get(0)).getComment(), is(equalTo("Index 1")));
        assertThat(((ZestComment) processedStatements.get(1)).getComment(), is(equalTo("Index 2")));
        assertThat(((ZestComment) processedStatements.get(2)).getComment(), is(equalTo("Index 3")));
        assertThat(((ZestComment) processedStatements.get(3)).getComment(), is(equalTo("Index 4")));
    }

    @Test
    void shouldIgnoreStatementsNotStartingAtOne() throws Exception {
        // Given / When
        reorderer.recordStatement(createJsonStatement(2));
        reorderer.recordStatement(createJsonStatement(3));
        reorderer.recordStatement(createJsonStatement(4));

        // Then
        assertThat(processedStatements.size(), is(equalTo(0)));
    }

    @Test
    void shouldNotProcessStatementsIfGap() throws Exception {
        // Given / When
        reorderer.recordStatement(createJsonStatement(1));
        reorderer.recordStatement(createJsonStatement(2));
        reorderer.recordStatement(createJsonStatement(3));
        reorderer.recordStatement(createJsonStatement(5));
        reorderer.recordStatement(createJsonStatement(6));
        reorderer.recordStatement(createJsonStatement(7));

        // Then
        assertThat(processedStatements.size(), is(equalTo(3)));
        assertThat(((ZestComment) processedStatements.get(0)).getComment(), is(equalTo("Index 1")));
        assertThat(((ZestComment) processedStatements.get(1)).getComment(), is(equalTo("Index 2")));
        assertThat(((ZestComment) processedStatements.get(2)).getComment(), is(equalTo("Index 3")));
    }

    @Test
    void shouldThrowExceptionIfNoIndex() {
        // Given / When
        JSONObject stmt = createJsonStatement(1);
        stmt.remove("index");

        // Then
        assertThrows(JSONException.class, () -> reorderer.recordStatement(stmt));
    }

    @Test
    void shouldThrowExceptionIfBadZestStatement() {
        // Given / When
        JSONObject stmt = createJsonStatement(1);
        stmt.remove("elementType");

        // Then
        assertThrows(Exception.class, () -> reorderer.recordStatement(stmt));
    }

    private static JSONObject createJsonStatement(int index) {
        JSONObject json = new JSONObject();
        json.put("index", index);
        json.put("elementType", "ZestComment");
        json.put("comment", "Index " + index);
        return json;
    }
}
