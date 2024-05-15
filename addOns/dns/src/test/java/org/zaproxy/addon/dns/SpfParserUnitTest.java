/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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
package org.zaproxy.addon.dns;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.zaproxy.addon.dns.exceptions.TooManyRecordsException;

class SpfParserUnitTest {
    @Test
    void txtRecordsBaseCase() throws TooManyRecordsException {
        // Given
        List<String> records = List.of("v=spf1 -all");
        // When
        SpfParser sut = new SpfParser(records);
        // Then
        assertThat(sut.hasSpfRecord(), is(true));
    }

    @Test
    void noTxtRecordsFindsNoSpfRecord() throws TooManyRecordsException {
        // Given
        List<String> records = List.of();
        // When
        SpfParser sut = new SpfParser(records);
        // Then
        assertThat(sut.hasSpfRecord(), is(false));
    }

    @Test
    void txtRecordsWithoutSpfFindsNoSpfRecord() throws TooManyRecordsException {
        // Given
        List<String> records = List.of("foo-verification=foo", "bar-verification=bar");
        // When
        SpfParser sut = new SpfParser(records);
        // Then
        assertThat(sut.hasSpfRecord(), is(false));
    }

    @Test
    void severalSpfRecordsRaiseAnException() {
        // Given
        List<String> records = List.of("v=spf1 -all", "v=spf1 -all");
        // When / Then
        assertThrows(TooManyRecordsException.class, () -> new SpfParser(records));
    }
}
