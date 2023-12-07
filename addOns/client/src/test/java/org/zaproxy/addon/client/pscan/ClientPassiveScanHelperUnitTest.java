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
package org.zaproxy.addon.client.pscan;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;

import java.util.Base64;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit test for {@link ClientPassiveScanHelper}. */
class ClientPassiveScanHelperUnitTest extends TestUtils {

    @ParameterizedTest
    @ValueSource(strings = {"test123", "{\"'\\:, []]", "@!£$%^&*(_)\n\r\t\\u00A9"})
    void shouldDecodePrintableBase64Strings(String str) {
        // Given / When
        String decoded =
                ClientPassiveScanHelper.base64Decode(
                        Base64.getEncoder().encodeToString(str.getBytes()));
        // Then
        assertThat(decoded, is(str));
    }

    @ParameterizedTest
    @ValueSource(strings = {"\u0000", "\b", ""})
    void shouldNotDecodeUnprintableBase64Strings(String str) {
        // Given / When
        String decoded =
                ClientPassiveScanHelper.base64Decode(
                        Base64.getEncoder().encodeToString(str.getBytes()));
        // Then
        assertThat(decoded, is(nullValue()));
    }
}
