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
package org.zaproxy.addon.commonlib;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** Unit test for {@link PiiUtils}. */
class PiiUtilsUnitTest {

    @ParameterizedTest
    @ValueSource(
            strings = {
                "4111111111111111",
                "4532015112830366",
                "5500005555555559",
                "5105105105105100",
                "371449635398431",
                "378282246310005",
                "6011111111111117",
                "6011000990139424",
            })
    void shouldPassLuhnCheckForValidCreditCardNumber(String cardNumber) {
        assertThat(PiiUtils.isValidLuhn(cardNumber), is(true));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "1234567890123456",
                "4532015112830367",
                "4111111111111112",
                "0000000000000001",
                "1111111111111111",
            })
    void shouldFailLuhnCheckForInvalidCreditCardNumber(String cardNumber) {
        assertThat(PiiUtils.isValidLuhn(cardNumber), is(false));
    }
}
