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
package org.zaproxy.addon.mcp.resources;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import java.util.Locale;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.Model;
import org.zaproxy.zap.utils.I18N;

/** Unit tests for {@link HistoryResource}. */
class HistoryResourceUnitTest {

    private ExtensionLoader extensionLoader;
    private ExtensionHistory extHistory;
    private HistoryResource resource;

    @BeforeEach
    void setUp() {
        Constant.messages = new I18N(Locale.ROOT);
        extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        extHistory = mock(ExtensionHistory.class, withSettings().strictness(Strictness.LENIENT));
        given(extensionLoader.getExtension(ExtensionHistory.class)).willReturn(extHistory);
        Control.initSingletonForTesting(mock(Model.class), extensionLoader);
        resource = new HistoryResource();
    }

    @Test
    void shouldHaveCorrectUriAndName() {
        assertThat(resource.getUri(), equalTo("zap://history"));
        assertThat(resource.getName(), equalTo("history"));
    }

    @Test
    void shouldReturnSummaryWithCountFromExtensionHistory() {
        given(extHistory.getLastHistoryId()).willReturn(42);

        assertThat(
                resource.readContent(),
                equalTo("{\"count\":42,\"note\":\"!mcp.resource.history.summary.note!\"}"));
    }
}
