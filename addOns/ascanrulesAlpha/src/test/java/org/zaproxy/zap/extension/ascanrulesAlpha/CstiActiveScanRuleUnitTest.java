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
package org.zaproxy.zap.extension.ascanrulesAlpha;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.lang.reflect.Method;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class CstiActiveScanRuleUnitTest {

    private CstiActiveScanRule rule;
    private Method stripQueryAndFragmentMethod;

    @BeforeEach
    void setUp() throws Exception {
        rule = new CstiActiveScanRule();
        stripQueryAndFragmentMethod =
                CstiActiveScanRule.class.getDeclaredMethod("stripQueryAndFragment", String.class);
        stripQueryAndFragmentMethod.setAccessible(true);
    }

    @ParameterizedTest
    @MethodSource("stripQueryAndFragmentCases")
    void shouldStripQueryAndFragment(String input, String expected) throws Exception {
        assertEquals(expected, invokeStripQueryAndFragment(input));
    }

    private String invokeStripQueryAndFragment(String value) throws Exception {
        return (String) stripQueryAndFragmentMethod.invoke(rule, value);
    }

    private static Stream<Arguments> stripQueryAndFragmentCases() {
        return Stream.of(
                Arguments.of(null, null),
                Arguments.of("", ""),
                Arguments.of("http://example.com/path", "http://example.com/path"),
                Arguments.of("http://example.com/path?name=value", "http://example.com/path"),
                Arguments.of("http://example.com/path#fragment", "http://example.com/path"),
                Arguments.of(
                        "http://example.com/path?name=value#fragment", "http://example.com/path"),
                Arguments.of(
                        "http://example.com/path#fragment?name=value", "http://example.com/path"),
                Arguments.of("?name=value", ""),
                Arguments.of("#fragment", ""));
    }
}
