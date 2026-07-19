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
package org.zaproxy.addon.commonlib.binlist;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVRecord;
import org.apache.commons.io.input.BOMInputStream;
import org.junit.jupiter.api.Test;

/** Unit test for {@link BinList}. */
class BinListUnitTest {

    @Test
    void shouldCreateBinList() {
        // Given / When
        BinList binList = assertDoesNotThrow(() -> BinList.getSingleton());
        // Then
        assertThat(binList, is(notNullValue()));
    }

    @Test
    void shouldGetValidBinRecord() {
        // Given
        String candidate = "324000";
        // When
        BinRecord record = BinList.getSingleton().get(candidate);
        // Then
        assertThat(record, is(notNullValue()));
        assertThat(record.getBin(), is(equalTo("324000")));
    }

    @Test
    void shouldNotGetInvalidBinRecord() {
        // Given
        String candidate = "Not a bin";
        // When
        BinRecord record = BinList.getSingleton().get(candidate);
        // Then
        assertThat(record, is(nullValue()));
    }

    @Test
    void shouldHaveSixDigitBins() throws Exception {
        try (InputStream in = BinList.class.getResourceAsStream("binlist-data.csv");
                BOMInputStream bomStream = BOMInputStream.builder().setInputStream(in).get();
                InputStreamReader inStream =
                        new InputStreamReader(bomStream, StandardCharsets.UTF_8)) {
            for (CSVRecord rec :
                    CSVFormat.Builder.create()
                            .setHeader()
                            .setSkipHeaderRecord(true)
                            .get()
                            .parse(inStream)) {
                assertThat(rec.get("BIN").length(), is(equalTo(6)));
            }
        }
    }
}
