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
package org.zaproxy.addon.dns;

import java.util.List;
import org.zaproxy.addon.dns.exceptions.TooManyRecordsException;

public class SpfParser {

    private String record = null;

    public SpfParser(List<String> txtRecord) throws TooManyRecordsException {
        for (String entry : txtRecord) {
            if (!entry.startsWith("v=spf1 ")) {
                continue;
            }
            if (record != null) {
                throw new TooManyRecordsException();
            }
            record = entry;
        }
    }

    public boolean hasSpfRecord() {
        return record != null;
    }
}
