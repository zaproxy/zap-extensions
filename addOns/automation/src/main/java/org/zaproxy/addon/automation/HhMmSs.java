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

import java.text.ParseException;
import java.util.concurrent.TimeUnit;

public class HhMmSs {

    private long timeInMs;
    private static final String SEPARATOR = ":";

    public HhMmSs(String timeStr) throws ParseException, NumberFormatException {
        if (timeStr == null) {
            // Cope with no string - default to 0
            return;
        }
        int minusIndex = timeStr.indexOf("-");
        if (minusIndex >= 0) {
            throw new ParseException(timeStr, minusIndex);
        }

        String[] units = timeStr.split(SEPARATOR);
        int offset = 0;
        if (units.length > 3) {
            throw new ParseException(timeStr, timeStr.lastIndexOf(SEPARATOR));
        }
        if (units.length == 3) {
            timeInMs = TimeUnit.HOURS.toMillis(parse(units[offset]));
            offset++;
        }
        if (units.length >= 2) {
            timeInMs += TimeUnit.MINUTES.toMillis(parse(units[offset]));
            offset++;
        }
        timeInMs += TimeUnit.SECONDS.toMillis(parse(units[offset]));
    }

    private static long parse(String str) {
        if (str.isEmpty()) {
            return 0;
        }
        return Integer.parseInt(str);
    }

    public long getTimeInMs() {
        return timeInMs;
    }
}
