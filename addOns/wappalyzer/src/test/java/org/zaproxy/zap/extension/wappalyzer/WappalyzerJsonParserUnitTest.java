/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.Test;

class WappalyzerJsonParserUnitTest {

    @Test
    void shouldParseExample() {
        // Given
        WappalyzerJsonParser wjp = new WappalyzerJsonParser();
        WappalyzerData wappData =
                wjp.parse("categories.json", Collections.singletonList("apps.json"));
        List<String> expectedCategory = new ArrayList<>(1);
        expectedCategory.add("Advertising"); // 36 - Advertising
        // When
        List<Application> apps = wappData.getApplications();
        Application app = apps.get(0);
        // Then
        assertEquals(6, apps.size());
        assertEquals("Test Entry", app.getName());
        assertEquals("Test Entry is a test entry for UnitTests", app.getDescription());
        assertEquals("https://www.example.com/testentry", app.getWebsite());
        assertEquals(expectedCategory, app.getCategories());
        assertEquals(1, app.getHeaders().size());
        assertEquals(1, app.getUrl().size());
        assertEquals(2, app.getHtml().size());
        assertEquals(2, app.getScript().size());
        assertEquals(2, app.getMetas().size());
        assertEquals(0, app.getImplies().size());
        assertEquals(2, app.getDom().size());
        assertEquals("", app.getCpe());

        app = apps.get(1);
        assertEquals(1, app.getSimpleDom().size());
        // Ignore Icon

        app = apps.get(3);
        assertEquals("Apache", app.getName());
        assertEquals(1, app.getMetas().size());
    }
}
