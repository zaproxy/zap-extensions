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
package org.zaproxy.addon.automation;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.text.ParseException;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

class HhMmSsUnitTest {

    @ParameterizedTest
    @ValueSource(strings = {"-1", "-1:10", "-1:20:20", "10:-2:20", "-1:-2:-3", "10:20:-30"})
    void shouldRejectNegativeValues(String hhmmss) {
        ParseException exception = assertThrows(ParseException.class, () -> new HhMmSs(hhmmss));
        assertThat(exception.getErrorOffset(), is(equalTo(hhmmss.indexOf('-'))));
    }

    @Test
    void shouldRejectTooManyColons() {
        String str = "1:2:3:4";
        ParseException exception = assertThrows(ParseException.class, () -> new HhMmSs(str));
        assertThat(exception.getErrorOffset(), is(equalTo(str.lastIndexOf(":"))));
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 1, 20, 100, 10000})
    void shouldParseSs(int timeInSecs) throws ParseException {
        // Given
        HhMmSs hhmmss = new HhMmSs(Integer.toString(timeInSecs));

        // When
        long time = hhmmss.getTimeInMs();

        // Then
        assertThat(time, is(equalTo(TimeUnit.SECONDS.toMillis(timeInSecs))));
    }

    @ParameterizedTest
    @CsvSource(value = {"0,0", "0,1", "10,00", "100,100"})
    void shouldParseMmSs(String mmStr, String ssStr) throws ParseException {
        // Given
        HhMmSs hhmmss = new HhMmSs(mmStr + ":" + ssStr);

        // When
        long time = hhmmss.getTimeInMs();

        // Then
        assertThat(
                time,
                is(
                        equalTo(
                                TimeUnit.MINUTES.toMillis(Integer.parseInt(mmStr))
                                        + TimeUnit.SECONDS.toMillis(Integer.parseInt(ssStr)))));
    }

    @ParameterizedTest
    @CsvSource(value = {"0,0,0", "0,0,1", "0,10,00", "10,0,0", "1000,1000,1000"})
    void shouldParseHhMmSs(String hhStr, String mmStr, String ssStr) throws ParseException {
        // Given
        HhMmSs hhmmss = new HhMmSs(hhStr + ":" + mmStr + ":" + ssStr);

        // When
        long time = hhmmss.getTimeInMs();

        // Then
        assertThat(
                time,
                is(
                        equalTo(
                                TimeUnit.HOURS.toMillis(Integer.parseInt(hhStr))
                                        + TimeUnit.MINUTES.toMillis(Integer.parseInt(mmStr))
                                        + TimeUnit.SECONDS.toMillis(Integer.parseInt(ssStr)))));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "0:", ":0", ":0:0", "0::", "::0"})
    void shouldHandleEmptyValues(String hhMmSsStr) throws ParseException {
        // Given
        HhMmSs hhmmss = new HhMmSs(hhMmSsStr);

        // When
        long time = hhmmss.getTimeInMs();

        // Then
        assertThat(time, is(equalTo(0L)));
    }
}
