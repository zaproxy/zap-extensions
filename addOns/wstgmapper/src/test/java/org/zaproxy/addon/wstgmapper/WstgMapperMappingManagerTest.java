/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.addon.wstgmapper;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;

import java.io.IOException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link WstgMapperMappingManager}.
 *
 * <p>They verify the bundled plugin and technology mappings and guard that the mapper stays aligned
 * with the official WSTG add-on's packaged mapping data.
 */
class WstgMapperMappingManagerTest {

    private WstgMapperMappingManager manager;

    @BeforeEach
    void setUp() throws IOException {
        manager = new WstgMapperMappingManager();
    }

    @Test
    void loadsWithoutException() {
        // setUp() instantiates without throwing — just reaching this point is enough.
    }

    @Test
    void knownPluginIdReturnsMappedWstgIds() {
        // Plugin 10010 → WSTG-SESS-02 as per mappings.json
        assertThat(manager.getWstgIdsForPlugin(10010), contains("WSTG-SESS-02"));
    }

    @Test
    void unknownPluginIdReturnsEmptySet() {
        assertThat(manager.getWstgIdsForPlugin(Integer.MAX_VALUE), is(empty()));
    }

    @Test
    void officialRepositoryPluginIdsRemainMapped() {
        assertThat(manager.getWstgIdsForPlugin(10012), contains("WSTG-ATHN-06"));
        assertThat(manager.getWstgIdsForPlugin(7000001), contains("WSTG-ATHN-04"));
    }

    @Test
    void mappingsContainAtLeastOneEntry() {
        // Plugin 10011 is also mapped in the bundled data
        assertThat(manager.getWstgIdsForPlugin(10011), is(not(empty())));
    }

    @Test
    void technologyLookupIsCaseInsensitive() {
        // Load a technology that should be present in the bundled mappings.json
        // Use a known key and confirm upper/lower case both resolve
        var lower = manager.getWstgIdsForTechnology("mysql");
        var upper = manager.getWstgIdsForTechnology("MySQL");
        assertThat(lower, is(upper));
    }

    @Test
    void unknownTechnologyReturnsEmptySet() {
        assertThat(manager.getWstgIdsForTechnology("__no_such_technology_xyzzy__"), is(empty()));
    }
}
