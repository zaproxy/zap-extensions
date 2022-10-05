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
package org.zaproxy.addon.reports.sarif;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class SarifBigContentShrinkerUnitTest {

    private SarifBigContentShrinker shrinkerToTest;

    @BeforeEach
    void beforeEach() {
        shrinkerToTest = new SarifBigContentShrinker();
    }

    @CsvSource({
        "l2345,2,l2",
        "l2345,5,l2345",
        "l2345,10,l2345",
        ",0,",
        "abcdefg,0,''",
        ",-2,",
        "abcdefg,-2,''",
        ",5,",
        ",-1,",
        "l2345,-1,''",
        "'',-1,''",
        "'',10,''"
    })
    @ParameterizedTest(name = "\"{0}\", maximum: {1} results in \"{2}\"")
    void shrinkTextWithoutMarkers(String evidence, int maximum, String expectedResult) {
        /* execute */
        String result = shrinkerToTest.shrinkTextWithoutMarkers(evidence, maximum);

        /* test */
        assertEquals(expectedResult, result);
    }

    @CsvSource({"0", "10", "1", "-1", "-10"})
    @ParameterizedTest(name = "null, maximum: {0} results in null")
    void shrinkTextWithoutMarkersNullString(int maximum) {
        /* execute */
        String result = shrinkerToTest.shrinkTextWithoutMarkers(null, maximum);

        /* test */
        assertNull(result);
    }

    @CsvSource({
        "4,5,4",
        "10,11,10",
        "10,2,2",
        "0,5,0",
        "0,0,0",
        "1,1,1",
        "30,1,1",
        "4,0,0",
        "4,-1,0",
        "5,-2,0"
    })
    @ParameterizedTest(
            name = "an array having {0} bytes, maximum: {1} results in array with {2} bytes")
    void byteArrayShrinkingAsExpected(int givenArraySize, int maximum, int expectedArraySize) {
        /* prepare */
        byte[] givenArray = new byte[givenArraySize];
        for (int i = 0; i < givenArraySize; i++) {
            givenArray[i] = (byte) i;
        }
        /* execute */
        byte[] result = shrinkerToTest.shrinkBytesArray(givenArray, maximum);

        /* test */
        assertNotNull(result);
        assertEquals(expectedArraySize, result.length);
        for (int i = 0; i < expectedArraySize; i++) {
            assertEquals((byte) i, result[i]);
        }
    }

    @CsvSource({"0", "10", "1", "-1", "-10"})
    @ParameterizedTest(name = "null, maximum: {0} results in null")
    void byteArrayShrinkingWithArrayNullandDifferentMaximum(int maximum) {
        /* execute */
        byte[] result = shrinkerToTest.shrinkBytesArray(null, maximum);

        /* test */
        assertNull(result);
    }

    @CsvSource({
        "12345678901234567890,,30,12345678901234567890",
        "12345678901234567890,12345678901234567890,30,12345678901234567890",
        "12345678901234567890,,15,123456789012345[...]",
        "12345678901234567890,not-found,15,123456789012345[...]",
        "1234567890abcd1234567890,abcd,2,ab[...]",
        "1234567890abcd1234567890,abcd,14,[...]67890abcd12345[...]",
        "12345678901234567890abcd,abcd,14,[...]67890abcd",
        "12345678901234567890abcd12345,abcd,14,[...]67890abcd12345",
    })
    @ParameterizedTest(name = "\"{0}\", snippet:\"{1}\" maximum: {2} results in \"{2}\"")
    void shrinkTextToSnippetAreaWithMarkers(
            String content, String snippet, int maxAllowed, String expected) {
        /* prepare */
        int maxAllowedChars = 30;

        /* execute */
        String result =
                shrinkerToTest.shrinkTextToSnippetAreaWithMarkers(
                        content, maxAllowedChars, snippet);

        /* test */
        assertEquals(content, result);
    }
}
