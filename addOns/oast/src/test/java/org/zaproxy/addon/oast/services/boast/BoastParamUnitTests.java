/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.addon.oast.services.boast;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

import java.util.Locale;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.utils.I18N;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

class BoastParamUnitTests {

    @BeforeEach
    void setUp() {
        Constant.messages = new I18N(Locale.ROOT);
    }

    @Test
    void shouldNotReturnPollingFrequencyLessThanMinimum() {
        // Given
        BoastParam param = spy(new BoastParam());
        when(param.getConfig()).thenReturn(new ZapXmlConfiguration());

        // When
        param.setPollingFrequency(BoastParam.MINIMUM_POLLING_FREQUENCY - 1);

        // Then
        assertThat(param.getPollingFrequency(), is(BoastParam.MINIMUM_POLLING_FREQUENCY));
        assertThat(
                param.getConfig().getInt(BoastParam.PARAM_POLLING_FREQUENCY),
                is(BoastParam.MINIMUM_POLLING_FREQUENCY));
    }
}
