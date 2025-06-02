/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.addon.paramdigger;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.testutils.TestUtils;

class UtilsUnitTest extends TestUtils {

    private static String TEST_WORDLIST_FILE = "wordlists/test_list.txt";
    private Path file;

    @BeforeEach
    void init() throws Exception {
        setUpZap();
        try (InputStream is = UtilsUnitTest.class.getResourceAsStream("/" + TEST_WORDLIST_FILE)) {
            this.file = Paths.get(Constant.getZapHome(), TEST_WORDLIST_FILE);
            Files.createDirectories(file.getParent());
            Files.copy(is, file);
        }
    }

    @Test
    void shouldLoadFileWithoutErrors() throws IOException {
        // Given / When
        List<String> params = Utils.read(this.file);

        // Then
        assertThat(params, hasSize(60));
        assertEquals(params.get(10), "Id");
    }

    @Test
    void shouldPopulateMapWithoutErrors() {
        // Given / When
        List<String> params = Utils.read(this.file);
        Map<String, String> map = Utils.populate(params);

        // Then
        assertEquals(map.size(), 60);
        assertEquals(map.get("Id"), "111110");
        assertEquals(map.get("add_to_wishlist"), "111151");
    }

    @Test
    void shouldSliceWithoutErrors() {
        // Given / When
        List<String> params = Utils.read(this.file);
        Map<String, String> map = Utils.populate(params);
        List<Map<String, String>> sliced = Utils.slice(map, 2);

        // Then
        assertThat(sliced, hasSize(2));
        assertThat(sliced.get(0).size(), equalTo(30));
    }

    @Test
    void shouldGetQueryStringWithoutErrors() {
        // Given
        Map<String, String> map = new HashMap<>();
        map.put("q", "test");
        map.put("admin", "true");

        // When
        String queryString = Utils.createQueryString(map);

        // Then
        assertEquals(queryString, "?q=test&admin=true");
    }

    @Test
    void shouldGetUsableParamsWithoutErrors() {
        // Given
        Map<String, String> map1 = new HashMap<>();
        map1.put("q", "test");
        map1.put("admin", "true");
        Map<String, String> map2 = new HashMap<>();
        map2.put("id", "test");
        List<Map<String, String>> params = new ArrayList<>();
        params.add(map1);
        params.add(map2);

        // When
        List<Map<String, String>> usableParams = new ArrayList<>();
        params = Utils.confirmUsableParameters(params, usableParams);

        // Then
        assertEquals(params.size(), 1);
        assertEquals(params.get(0).get("q"), "test");
        assertEquals(params.get(0).get("admin"), "true");
        assertEquals(usableParams.size(), 1);
        assertEquals(usableParams.get(0).get("id"), "test");
    }

    @Test
    void shouldGetXmlStringWithoutErrors() {
        // Given
        Map<String, String> map = new HashMap<>();
        map.put("q", "test");
        map.put("admin", "true");

        // When
        String xmlString = Utils.createXmlString(map);

        // Then
        assertEquals(xmlString, "<q>test</q><admin>true</admin>");
    }
}
