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
package org.zaproxy.zap.extension.zest.dialogs;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.is;

import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.zaproxy.zap.extension.zest.ExtensionZest;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit test for {@link ShadowPathTableModel}. */
class ShadowPathTableModelUnitTest extends TestUtils {

    @BeforeAll
    static void setUpAll() {
        mockMessages(new ExtensionZest());
    }

    @Test
    void shouldStartEmpty() {
        // Given / When
        ShadowPathTableModel model = new ShadowPathTableModel();
        // Then
        assertThat(model.getRowCount(), is(0));
        assertThat(model.getValues(), is(empty()));
    }

    @Test
    void shouldAddReplaceAndRemoveSelectors() {
        // Given
        ShadowPathTableModel model = new ShadowPathTableModel();
        // When
        model.add("#a");
        model.add("#b");
        model.replace(0, "#c");
        model.remove(1);
        // Then
        assertThat(model.getRowCount(), is(1));
        assertThat(model.getValueAt(0, 0), is("#c"));
        assertThat(model.getValues(), contains("#c"));
    }

    @Test
    void shouldCopyValuesWhenSet() {
        // Given
        ShadowPathTableModel model = new ShadowPathTableModel();
        List<String> values = List.of("#a", "#b");
        // When
        model.setValues(values);
        model.add("#c");
        // Then
        assertThat(model.getValues(), contains("#a", "#b", "#c"));
    }
}
