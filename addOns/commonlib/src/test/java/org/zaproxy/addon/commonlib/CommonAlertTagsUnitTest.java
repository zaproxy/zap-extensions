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
package org.zaproxy.addon.commonlib;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;
import org.junit.jupiter.api.Test;

class CommonAlertTagsUnitTest {

    private static final Map<String, String> BASE_TAGS =
            CommonAlertTag.toMap(
                    CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG,
                    CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG,
                    CommonAlertTag.WSTG_V42_CONF_05_ENUMERATE_INFRASTRUCTURE);

    @Test
    void shouldAddAlertTagToMap() {
        // Given / When
        Map<String, String> allTags =
                CommonAlertTag.mergeTags(BASE_TAGS, CommonAlertTag.CUSTOM_PAYLOADS);
        // Then
        assertThat(allTags.size(), is(equalTo(4)));
        assertTrue(allTags.containsKey(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()));
        assertTrue(allTags.containsKey(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()));
        assertTrue(
                allTags.containsKey(
                        CommonAlertTag.WSTG_V42_CONF_05_ENUMERATE_INFRASTRUCTURE.getTag()));
        assertTrue(allTags.containsKey(CommonAlertTag.CUSTOM_PAYLOADS.getTag()));
    }

    @Test
    void shouldAddMultipleAlertTagsToMap() {
        // Given / When
        Map<String, String> allTags =
                CommonAlertTag.mergeTags(
                        BASE_TAGS,
                        CommonAlertTag.CUSTOM_PAYLOADS,
                        CommonAlertTag.WSTG_V42_SESS_09_SESS_HIJACK);
        // Then
        assertThat(allTags.size(), is(equalTo(5)));
        assertTrue(allTags.containsKey(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()));
        assertTrue(allTags.containsKey(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()));
        assertTrue(
                allTags.containsKey(
                        CommonAlertTag.WSTG_V42_CONF_05_ENUMERATE_INFRASTRUCTURE.getTag()));
        assertTrue(allTags.containsKey(CommonAlertTag.CUSTOM_PAYLOADS.getTag()));
        assertTrue(allTags.containsKey(CommonAlertTag.WSTG_V42_SESS_09_SESS_HIJACK.getTag()));
    }
}
