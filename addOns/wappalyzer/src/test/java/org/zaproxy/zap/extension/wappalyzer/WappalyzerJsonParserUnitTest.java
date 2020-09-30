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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

public class WappalyzerJsonParserUnitTest {

    @Test
    public void shouldParseExample() {
        // Given
        WappalyzerJsonParser wjp = new WappalyzerJsonParser();
        WappalyzerData wappData = wjp.parseAppsJson("apps.json");
        List<String> expectedCategory = new ArrayList<String>(1);
        expectedCategory.add("Advertising"); // 36 - Advertising
        // When
        List<Application> apps = wappData.getApplications();
        Application app = apps.get(0);
        // Then
        assertEquals(5, apps.size());
        assertTrue(app.getName().equals("Test Entry"));
        assertTrue(app.getDescription().equals("Test Entry is a test entry for UnitTests"));
        assertTrue(app.getWebsite().equals("https://www.example.com/testentry"));
        assertEquals(expectedCategory, app.getCategories());
        assertEquals(1, app.getHeaders().size());
        assertEquals(1, app.getUrl().size());
        assertEquals(2, app.getHtml().size());
        assertEquals(2, app.getScript().size());
        assertEquals(0, app.getMetas().size());
        assertEquals(0, app.getImplies().size());
        assertTrue(app.getCpe().equals(""));
        // Ignore Icon
    }
}
