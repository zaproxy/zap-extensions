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
import static org.junit.jupiter.api.Assertions.fail;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

class SarifHeaderCredentialHiderUnitTest {

    private SarifHeaderCredentialHider hiderToTest;

    @BeforeEach
    void beforeEach() {
        hiderToTest = new SarifHeaderCredentialHider();
    }

    @Test
    void keyNullAndValueNull() {
        assertEquals(
                null,
                hiderToTest.createSafeHeaderValue(null, null),
                " Header value must be unchanged, but was tampered!");
    }

    @ParameterizedTest
    @CsvSource({
        "unknown,value1",
        "key-with-value-null,",
        ",value-for-key-null",
        "age,128404",
        "X-Forwarded-Host,test.example.org:8080",
        "!Authorization,value"
    })
    void defaultIsToReturnJustTheValue(String headerName, String headerValue) {
        assertEquals(
                headerValue,
                hiderToTest.createSafeHeaderValue(headerName, headerValue),
                " Header value must be unchanged, but was tampered!");
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "Basic dXNlcjpwYXNzd29yZA==",
                "Basic dXNlcjpwYXNzd29yZA==  ",
                "Basic    dXNlcjpwYXNzd29yZA==",
                "   Basic dXNlcjpwYXNzd29yZA==",
                "BASIC dXNlcjpwYXNzd29yZA==",
                "basic dXNlcjpwYXNzd29yZA==",
                "something-else",
                "Basic XYZ"
            })
    void authorizationWithBasicAuthIsHidden(String headerValue) {

        assertValueIsHiddenWithAsterisks("Authorization", headerValue);
        assertValueIsHiddenWithAsterisks("authorization", headerValue);
        assertValueIsHiddenWithAsterisks("AUTHORIZATION", headerValue);
    }

    private void assertValueIsHiddenWithAsterisks(String headerName, String originHeaderValue) {
        String result = hiderToTest.createSafeHeaderValue(headerName, originHeaderValue);

        assertChangedToAsterisks(originHeaderValue, result);
    }

    private void assertChangedToAsterisks(String originHeaderValue, String result) {
        if (originHeaderValue.equals(result)) {
            fail("Origin header value kept:" + result);
        }

        for (char c : result.toCharArray()) {
            if (c != '*') {
                fail(
                        "Origin header value: "
                                + originHeaderValue
                                + " was changed to: "
                                + result
                                + ". Found character:"
                                + c
                                + " but should all be asterisks only!");
            }
        }
    }
}
