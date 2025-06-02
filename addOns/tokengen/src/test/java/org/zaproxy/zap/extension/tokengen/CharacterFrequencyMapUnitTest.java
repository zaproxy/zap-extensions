/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP Development Team
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
package org.zaproxy.zap.extension.tokengen;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;

import org.junit.jupiter.api.Test;

/** Unit test for {@link CharacterFrequencyMap}. */
class CharacterFrequencyMapUnitTest {

    @Test
    void shouldFailCharacterUniformityWithoutTokens() throws Exception {
        // Given
        CharacterFrequencyMap cfm = new CharacterFrequencyMap();
        // When
        TokenAnalysisTestResult result = cfm.checkCharacterUniformity();
        // Then
        assertThat(result.getType(), is(equalTo(TokenAnalysisTestResult.Type.CHR_UNIFORMITY)));
        assertThat(
                result.getName(), is(equalTo(TokenAnalysisTestResult.Type.CHR_UNIFORMITY.name())));
        assertThat(result.getResult(), is(equalTo(TokenAnalysisTestResult.Result.FAIL)));
        assertThat(result.getFailures(), is(contains("Tokens have zero characters.")));
        assertThat(result.getDetails(), is(empty()));
        assertThat(result.getSummary(), is(nullValue()));
    }

    @Test
    void shouldFailCharacterUniformityIfTokenCharsAreNotUniform() throws Exception {
        // Given
        CharacterFrequencyMap cfm = new CharacterFrequencyMap();
        for (int i = 0; i < 1000; i++) {
            cfm.addToken("ABC");
        }
        // When
        TokenAnalysisTestResult result = cfm.checkCharacterUniformity();
        // Then
        assertThat(result.getType(), is(equalTo(TokenAnalysisTestResult.Type.CHR_UNIFORMITY)));
        assertThat(
                result.getName(), is(equalTo(TokenAnalysisTestResult.Type.CHR_UNIFORMITY.name())));
        assertThat(result.getResult(), is(equalTo(TokenAnalysisTestResult.Result.FAIL)));
        assertThat(
                result.getFailures(),
                contains(
                        "Column 0 Character A appears 1000 times: more than expected (669)",
                        "Column 1 Character B appears 1000 times: more than expected (669)",
                        "Column 2 Character C appears 1000 times: more than expected (669)"));
        assertThat(
                result.getDetails(),
                is(
                        contains(
                                "Col 0 A:1000 B:0 C:0",
                                "Col 1 A:0 B:1000 C:0",
                                "Col 2 A:0 B:0 C:1000")));
        assertThat(result.getSummary(), is(nullValue()));
    }

    @Test
    void shouldPassCharacterUniformityIfTokensCharsAreUniform() throws Exception {
        // Given
        CharacterFrequencyMap cfm = new CharacterFrequencyMap();
        cfm.addToken("ABC");
        cfm.addToken("BCA");
        cfm.addToken("CAB");
        // When
        TokenAnalysisTestResult result = cfm.checkCharacterUniformity();
        // Then
        assertThat(result.getType(), is(equalTo(TokenAnalysisTestResult.Type.CHR_UNIFORMITY)));
        assertThat(
                result.getName(), is(equalTo(TokenAnalysisTestResult.Type.CHR_UNIFORMITY.name())));
        assertThat(result.getResult(), is(equalTo(TokenAnalysisTestResult.Result.PASS)));
        assertThat(result.getFailures(), is(empty()));
        assertThat(
                result.getDetails(),
                contains("Col 0 A:1 B:1 C:1", "Col 1 A:1 B:1 C:1", "Col 2 A:1 B:1 C:1"));
        assertThat(result.getSummary(), is(nullValue()));
    }
}
