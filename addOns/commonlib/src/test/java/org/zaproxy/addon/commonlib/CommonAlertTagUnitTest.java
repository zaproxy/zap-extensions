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

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.zaproxy.zap.testutils.UrlTests;

class CommonAlertTagUnitTest implements UrlTests {

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

    @Test
    void shouldLinkifyCveIdentifierString() {
        // Given
        Map<String, String> allTags = new HashMap<>();
        String cve = "CVE-2020-1234";
        allTags.put(
                CommonAlertTag.CUSTOM_PAYLOADS.getTag(), CommonAlertTag.CUSTOM_PAYLOADS.getValue());
        // When
        CommonAlertTag.putCve(allTags, cve);
        String link = allTags.get(cve);
        // Then
        assertThat(allTags.size(), is(equalTo(2)));
        assertTrue(allTags.containsKey(CommonAlertTag.CUSTOM_PAYLOADS.getTag()));
        assertTrue(allTags.containsKey(cve));
        assertThat(link, is(equalTo("https://nvd.nist.gov/vuln/detail/CVE-2020-1234")));
    }

    @Test
    void shouldHaveValidTagUrls() {
        // Given
        List<String> urls =
                Stream.of(CommonAlertTag.values())
                        .map(CommonAlertTag::getValue)
                        .filter(Predicate.not(String::isBlank))
                        .toList();
        // When / Then
        shouldHaveValidUrls(urls);
    }

    @Test
    void shouldHaveValidCveUrl() {
        // Given
        Map<String, String> tags = new HashMap<>();
        CommonAlertTag.putCve(tags, "CVE-2020-1234");
        // When / Then
        shouldHaveValidUrls(List.of(tags.get("CVE-2020-1234")));
    }
}
