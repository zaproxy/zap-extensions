/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.addon.commonlib.http;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** Unit test for {@link HttpDateUtils}. */
public class HttpDateUtilsUnitTest {

    @ParameterizedTest
    @ValueSource(
            strings = {
                "Sun, 06 Nov 1994 08:49:37 GMT",
                "Sun, 06-Nov-1994 08:49:37 GMT",
                "Sunday, 06-Nov-94 08:49:37 GMT",
                "Sun Nov  6 08:49:37 1994"
            })
    void shouldParseKnownFormats(String date) {
        // Given / When
        ZonedDateTime parsedDate = HttpDateUtils.parse(date);
        // Then
        assertThat(parsedDate, is(notNullValue()));
        assertThat(parsedDate.getYear(), is(equalTo(1994)));
        assertThat(parsedDate.getMonthValue(), is(equalTo(11)));
        assertThat(parsedDate.getDayOfMonth(), is(equalTo(6)));
        assertThat(parsedDate.getHour(), is(equalTo(8)));
        assertThat(parsedDate.getMinute(), is(equalTo(49)));
        assertThat(parsedDate.getSecond(), is(equalTo(37)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "Unkown Format"})
    void shouldFailToParseUnknownFormats(String date) {
        // Given / When
        ZonedDateTime parsedDate = HttpDateUtils.parse(date);
        // Then
        assertThat(parsedDate, is(nullValue()));
    }

    @Test
    void shouldFormatInstant() {
        // Given
        Instant instant = Instant.ofEpochMilli(1621421285000L);
        // When
        String formattedDate = HttpDateUtils.format(instant);
        // Then
        assertThat(formattedDate, is(equalTo("Wed, 19 May 2021 10:48:05 GMT")));
    }

    public static List<DateTimeFormatter> formatters() {
        return HttpDateUtils.FORMATTERS;
    }
}
