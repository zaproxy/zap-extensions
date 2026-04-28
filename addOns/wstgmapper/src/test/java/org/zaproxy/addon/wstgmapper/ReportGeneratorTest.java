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
import static org.hamcrest.Matchers.containsString;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zaproxy.addon.wstgmapper.model.WstgCategory;
import org.zaproxy.addon.wstgmapper.model.WstgTest;
import org.zaproxy.addon.wstgmapper.model.WstgTestStatus;

/**
 * Unit tests for {@link ReportGenerator}.
 *
 * <p>These tests lock down the exported Markdown and CSV structure so report wording and field
 * placement stay predictable as the rest of the add-on evolves.
 */
class ReportGeneratorTest {

    private WstgMapperData data;
    private WstgMapperChecklistManager manager;
    private CoverageCalculator calculator;
    private ReportGenerator reportGenerator;

    @BeforeEach
    void setUp() {
        data =
                new WstgMapperData(
                        List.of(
                                new WstgCategory(
                                        "INFO",
                                        "Information Gathering",
                                        List.of(
                                                new WstgTest(
                                                        "WSTG-INFO-01",
                                                        "Fingerprint Web Server",
                                                        List.of("Objective"),
                                                        "How to test",
                                                        List.of("https://example.com/wstg"))))));
        manager = new WstgMapperChecklistManager(null);
        manager.triggerTests(Set.of("WSTG-INFO-01"));
        manager.setTestNotes("WSTG-INFO-01", "Triggered from passive scan.");
        manager.setTestStatus("WSTG-INFO-01", WstgTestStatus.PASSED);
        calculator =
                new CoverageCalculator(
                        data,
                        manager,
                        new WstgMapperMappingManager(
                                Map.of(10010, Set.of("WSTG-INFO-01")), Map.of()));
        reportGenerator =
                new ReportGenerator(
                        Clock.fixed(Instant.parse("2026-04-28T10:15:30Z"), ZoneOffset.UTC),
                        () -> "example.com",
                        "0.1.0");
    }

    @Test
    void generatesMarkdownSummary() {
        String markdown = reportGenerator.generateMarkdown(data, manager, calculator);

        assertThat(markdown, containsString("# WSTG Compliance Report"));
        assertThat(markdown, containsString("**Target:** example.com"));
        assertThat(markdown, containsString("**Date:** 2026-04-28"));
        assertThat(markdown, containsString("Effective coverage: 100.0%"));
        assertThat(
                markdown,
                containsString("| Information Gathering | INFO | 1 | 1 | 1 | 0 | 0 | 100.0% |"));
    }

    @Test
    void generatesCsvRows() {
        String csv = reportGenerator.generateCsv(data, manager, calculator);

        assertThat(
                csv, containsString("Category,Test ID,Test Name,Status,Triggered,Automated,Notes"));
        assertThat(
                csv,
                containsString(
                        "Information Gathering,WSTG-INFO-01,Fingerprint Web Server,PASSED,Yes,Yes,Triggered from passive scan."));
    }
}
