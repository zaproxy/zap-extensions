/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2019 The ZAP Development Team
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
package org.zaproxy.zap.extension.wappalyzer;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.Test;

public class WappalyzerAppsJsonParseUnitTest {

    @Test
    public void test() throws IOException {
        // Given
        List<String> errs = new ArrayList<>();
        List<Exception> parsingExceptions = new ArrayList<>();
        // When
        WappalyzerJsonParser parser =
                new WappalyzerJsonParser(
                        (pattern, e) -> errs.add(e.toString()), parsingExceptions::add);
        parser.parseDefaultAppsJson();
        // Then
        assertEquals(Collections.emptyList(), errs);
        assertEquals(Collections.emptyList(), parsingExceptions);
    }
}
