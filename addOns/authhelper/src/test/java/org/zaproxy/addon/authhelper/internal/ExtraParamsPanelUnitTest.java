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
package org.zaproxy.addon.authhelper.internal;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;

import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.authhelper.internal.ExtraParamsPanel.ExtraParamsTableModel;
import org.zaproxy.zap.utils.I18N;

/** Unit test for {@link ExtraParamsPanel}'s table model. */
class ExtraParamsPanelUnitTest {

    private ExtraParamsTableModel model;

    @BeforeEach
    void setUp() {
        Constant.messages = new I18N(java.util.Locale.ENGLISH);
        model = new ExtraParamsTableModel();
    }

    @Test
    void shouldStartEmpty() {
        assertThat(model.getElements(), empty());
        assertThat(model.getRowCount(), equalTo(0));
    }

    @Test
    void shouldKeepParamsAndOrder() {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("b", "2");
        params.put("audience", "https://api.example.com");
        params.put("a", "1");

        model.setParams(params);

        assertThat(model.getRowCount(), equalTo(3));
        assertThat(model.getColumnCount(), equalTo(2));
        assertThat(model.getValueAt(1, 0), equalTo("audience"));
        assertThat(model.getValueAt(1, 1), equalTo("https://api.example.com"));
        assertThat(
                model.getElements(),
                contains(
                        new ExtraParam("b", "2"),
                        new ExtraParam("audience", "https://api.example.com"),
                        new ExtraParam("a", "1")));
    }

    @Test
    void shouldReplaceParamsOnSet() {
        model.setParams(Map.of("a", "1"));
        model.setParams(Map.of("b", "2"));

        assertThat(model.getElements(), hasSize(1));
        assertThat(model.getElements().get(0), equalTo(new ExtraParam("b", "2")));
    }

    @Test
    void shouldHandleNullParams() {
        model.setParams(Map.of("a", "1"));
        model.setParams(null);

        assertThat(model.getElements(), empty());
    }
}
