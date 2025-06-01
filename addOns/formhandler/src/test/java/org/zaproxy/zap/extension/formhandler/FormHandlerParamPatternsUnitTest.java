/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.zap.extension.formhandler;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

class FormHandlerParamPatternsUnitTest {

    private FormHandlerParam param;
    private ZapXmlConfiguration configuration;

    @BeforeEach
    void setUp() {
        param = new FormHandlerParam();
        configuration = new ZapXmlConfiguration();
        param.load(configuration);
    }

    @ParameterizedTest
    @ValueSource(strings = {"backlink", "_backlink", "_Back_link", "backUri", "_back-url"})
    void shouldMatchBacklinkParameters(String paramName) {
        // Given / When
        String value = param.getEnabledFieldValue(paramName);
        // Then
        assertThat(value, is(equalTo("https://zap.example.com")));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "_bgcolor",
                "_BgColor",
                "bgcolor",
                "bgcolour",
                "bg_color",
                "bg-Color",
                "_bg_color"
            })
    void shouldMatchBackgroundColorParameters(String paramName) {
        // Given / When
        String value = param.getEnabledFieldValue(paramName);
        // Then
        assertThat(value, is(equalTo("#FFFFFF")));
    }

    @ParameterizedTest
    @ValueSource(strings = {"_query", "Find", "KEYWORD", "keyWord"})
    void shouldMatchSearchParameters(String paramName) {
        // Given / When
        String value = param.getEnabledFieldValue(paramName);
        // Then
        assertThat(value, is(equalTo("ZAP")));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "search",
                "_Search",
                "searchterm",
                "_searchTerm",
                "search-term",
                "search_term",
                "_search_Term"
            })
    void shouldMatchPotentiallyExtendedSearchParameters(String paramName) {
        // Given / When
        String value = param.getEnabledFieldValue(paramName);
        // Then
        assertThat(value, is(equalTo("ZAP")));
    }

    @ParameterizedTest
    @ValueSource(strings = {"comment", "_Comment", "subject", "summary"})
    void shouldMatchShortSentenceFieldParameters(String paramName) {
        // Given / When
        String value = param.getEnabledFieldValue(paramName);
        // Then
        assertThat(value, is(equalTo("Zaproxy dolore alias impedit expedita quisquam.")));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "description",
                "message",
                "content",
                "_content",
                "emailContent",
                "_email_content",
                "post-Content"
            })
    void shouldMatchParagraphFieldParameters(String paramName) {
        // Given / When
        String value = param.getEnabledFieldValue(paramName);
        // Then
        assertThat(
                value,
                is(
                        equalTo(
                                "Zaproxy alias impedit expedita quisquam pariatur exercitationem. Nemo rerum eveniet dolores rem quia dignissimos.")));
    }

    @ParameterizedTest
    @ValueSource(strings = {"address", "_address", "Address_1", "address-1", "_address-1"})
    void shouldMatchAddressFieldParameters(String paramName) {
        // Given / When
        String value = param.getEnabledFieldValue(paramName);
        // Then
        assertThat(value, is(equalTo("688 Zaproxy Ridge")));
    }

    @ParameterizedTest
    @ValueSource(strings = {"address2", "_address2", "Address_2", "address-2", "_address-2"})
    void shouldMatchAddress2FieldParameters(String paramName) {
        // Given / When
        String value = param.getEnabledFieldValue(paramName);
        // Then
        assertThat(value, is(equalTo("Suite 473")));
    }
}
