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

import java.time.DateTimeException;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoField;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Utility class to parse/format HTTP related dates.
 *
 * @since 1.4.0
 */
public final class HttpDateUtils {

    private static final Logger LOGGER = LogManager.getLogger(HttpDateUtils.class);

    private static final DateTimeFormatter FORMATTER_RFC_1123 =
            DateTimeFormatter.RFC_1123_DATE_TIME.withLocale(Locale.ROOT);
    private static final DateTimeFormatter FORMATTER_RFC_1123_HYPHENS =
            DateTimeFormatter.ofPattern("EEE, dd-MMM-yyyy HH:mm:ss zzz", Locale.ROOT);
    private static final DateTimeFormatter FORMATTER_RFC_1036 =
            new DateTimeFormatterBuilder()
                    .parseCaseInsensitive()
                    .parseLenient()
                    .appendPattern("EEEE, dd-MMM-")
                    .appendValueReduced(
                            ChronoField.YEAR_OF_ERA, 2, 2, LocalDate.now().minusYears(50))
                    .appendPattern(" HH:mm:ss zzz")
                    .toFormatter(Locale.ENGLISH);
    private static final DateTimeFormatter FORMATTER_ASCTIME =
            DateTimeFormatter.ofPattern("EEE MMM ppd HH:mm:ss yyyy", Locale.ROOT)
                    .withZone(ZoneOffset.UTC);

    static final List<DateTimeFormatter> FORMATTERS =
            Arrays.asList(
                    FORMATTER_RFC_1123,
                    FORMATTER_RFC_1123_HYPHENS,
                    FORMATTER_RFC_1036,
                    FORMATTER_ASCTIME);

    private HttpDateUtils() {}

    /**
     * Parses the given date.
     *
     * <p>Several formats are supported.
     *
     * @param date the date as string.
     * @return the parsed date, or {@code null} if not able to parse it.
     */
    public static ZonedDateTime parse(String date) {
        if (date == null || date.isEmpty()) {
            return null;
        }

        for (DateTimeFormatter formatter : FORMATTERS) {
            try {
                return ZonedDateTime.parse(date, formatter);
            } catch (DateTimeParseException ex) {
                LOGGER.debug("Couldn't parse date {} with {} : {}", date, formatter, ex);
            }
        }
        return null;
    }

    /**
     * Formats the given instant.
     *
     * @param instant the instant to format.
     * @return the formatted date.
     * @throws DateTimeException if an error occurred while formatting the instant.
     */
    public static String format(Instant instant) {
        return FORMATTER_RFC_1123.format(instant.atOffset(ZoneOffset.UTC));
    }
}
