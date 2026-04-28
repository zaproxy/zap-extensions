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
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.is;

import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zaproxy.addon.wstgmapper.model.WstgCategory;
import org.zaproxy.addon.wstgmapper.model.WstgTest;

/**
 * Unit tests for {@link TechStackDetector}.
 *
 * <p>They verify that detected technologies expand to the expected tests and categories, which is
 * the basis for the tech-focused filtering exposed by the main panel.
 */
class TechStackDetectorTest {

    private WstgMapperChecklistManager checklistManager;
    private TechStackDetector detector;

    @BeforeEach
    void setUp() {
        WstgMapperData data =
                new WstgMapperData(
                        List.of(
                                new WstgCategory(
                                        "INFO",
                                        "Information Gathering",
                                        List.of(
                                                new WstgTest(
                                                        "WSTG-INFO-01",
                                                        "Server Fingerprinting",
                                                        List.of(),
                                                        "",
                                                        List.of()))),
                                new WstgCategory(
                                        "SESS",
                                        "Session Management",
                                        List.of(
                                                new WstgTest(
                                                        "WSTG-SESS-01",
                                                        "Session Schema",
                                                        List.of(),
                                                        "",
                                                        List.of())))));
        checklistManager = new WstgMapperChecklistManager(null);
        detector =
                new TechStackDetector(
                        new WstgMapperMappingManager(
                                Map.of(),
                                Map.of(
                                        "mysql", Set.of("WSTG-INFO-01"),
                                        "spring", Set.of("WSTG-SESS-01"))),
                        data);
    }

    @Test
    void resolvesRelevantTestsFromDetectedTechnologies() {
        checklistManager.addDetectedTechnology("MySQL");
        checklistManager.addDetectedTechnology("SPRING");

        assertThat(
                detector.getRelevantTestIds(checklistManager),
                containsInAnyOrder("WSTG-INFO-01", "WSTG-SESS-01"));
    }

    @Test
    void resolvesRelevantCategoriesFromDetectedTechnologies() {
        checklistManager.addDetectedTechnology("mysql");

        assertThat(detector.getRelevantCategoryIds(checklistManager), containsInAnyOrder("INFO"));
    }

    @Test
    void returnsEmptySetsWhenNoTechnologiesAreDetected() {
        assertThat(detector.getRelevantTestIds(checklistManager).isEmpty(), is(true));
        assertThat(detector.getRelevantCategoryIds(checklistManager).isEmpty(), is(true));
    }
}
