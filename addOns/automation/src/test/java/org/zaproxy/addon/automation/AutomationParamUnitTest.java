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
package org.zaproxy.addon.automation;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import org.apache.commons.configuration.ConfigurationException;
import org.junit.jupiter.api.Test;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/** Unit tests for {@link AutomationParam}. */
class AutomationParamUnitTest {

    @Test
    void shouldStartNewSessionPerBatchPlanByDefault() {
        // Given
        AutomationParam param = new AutomationParam();
        // When
        param.load(new ZapXmlConfiguration());
        // Then
        assertThat(param.isBatchNewSession(), is(equalTo(true)));
    }

    @Test
    void shouldSaveTheBatchDirectory() throws ConfigurationException {
        // Given
        ZapXmlConfiguration config = mock(ZapXmlConfiguration.class);
        AutomationParam param = new AutomationParam();
        param.load(config);
        // When
        param.setBatchDirectory("/some/dir");
        // Then
        assertThat(param.getBatchDirectory(), is(equalTo("/some/dir")));
        verify(config).save();
    }
}
