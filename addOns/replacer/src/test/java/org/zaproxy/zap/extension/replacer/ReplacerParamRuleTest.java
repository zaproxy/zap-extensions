/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2019 The ZAP Development Team
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
package org.zaproxy.zap.extension.replacer;

import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.*;
import static org.zaproxy.zap.extension.replacer.ReplacerParamRule.MatchType.REQ_HEADER_STR;

import org.junit.Test;

public class ReplacerParamRuleTest {

    @Test
    public void shouldSubstituteHexValuesInReplacementString() {
        // Given
        String replacement = "abc\\x01\\xaadef";

        // When
        ReplacerParamRule nonAsciiRegexRule =
                new ReplacerParamRule(
                        "", REQ_HEADER_STR, "anyMatchString", true, replacement, null, true);

        // Then
        assertThat(
                nonAsciiRegexRule.getEscapedReplacement(),
                equalTo(new String(new byte[] {'a', 'b', 'c', 1, (byte) 170, 'd', 'e', 'f'})));
    }
}
