/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.addon.network.internal.ui;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.mock;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.network.internal.server.http.Alias;
import org.zaproxy.zap.utils.I18N;

/** Unit test for {@link AliasTableModel}. */
class AliasTableModelUnitTest {

    @BeforeAll
    static void setUpAll() {
        Constant.messages = mock(I18N.class);
    }

    @Test
    void shouldCreateCopyOfCollectionAndValues() {
        // Given
        AliasTableModel model = new AliasTableModel();
        List<Alias> passThroughs = new ArrayList<>();
        Alias original = new Alias("zap", false);
        passThroughs.add(original);
        // When
        model.setAliases(passThroughs);
        model.setAllEnabled(true);
        passThroughs.clear();
        // Then
        assertThat(original.isEnabled(), is(equalTo(false)));
        assertThat(model.getElements(), hasSize(1));
        assertThat(model.getElements().get(0).isEnabled(), is(equalTo(true)));
    }
}
