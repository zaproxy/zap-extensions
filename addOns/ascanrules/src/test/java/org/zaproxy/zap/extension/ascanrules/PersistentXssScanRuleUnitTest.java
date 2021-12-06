/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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
package org.zaproxy.zap.extension.ascanrules;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

import java.util.Map;
import org.junit.jupiter.api.Test;
import org.zaproxy.addon.commonlib.CommonAlertTag;

/** Unit test for {@link PersistentXssScanRule}. */
class PersistentXssScanRuleUnitTest extends ActiveScannerTest<PersistentXssScanRule> {

    @Override
    protected PersistentXssScanRule createScanner() {
        return new PersistentXssScanRule();
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        int cwe = rule.getCweId();
        int wasc = rule.getWascId();
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(cwe, is(equalTo(79)));
        assertThat(wasc, is(equalTo(8)));
        assertThat(tags.size(), is(equalTo(3)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A03_INJECTION.getTag()),
                is(equalTo(true)));
        assertThat(tags.containsKey(CommonAlertTag.OWASP_2017_A07_XSS.getTag()), is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.WSTG_V42_INPV_02_STORED_XSS.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A03_INJECTION.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A03_INJECTION.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A07_XSS.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A07_XSS.getValue())));
        assertThat(
                tags.get(CommonAlertTag.WSTG_V42_INPV_02_STORED_XSS.getTag()),
                is(equalTo(CommonAlertTag.WSTG_V42_INPV_02_STORED_XSS.getValue())));
    }
}
