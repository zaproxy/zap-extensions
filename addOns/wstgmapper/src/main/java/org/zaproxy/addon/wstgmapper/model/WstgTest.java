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
package org.zaproxy.addon.wstgmapper.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.List;

/**
 * Simple model object for a single OWASP WSTG test entry.
 *
 * <p>It carries the descriptive metadata shown in the detail panel, including objectives, testing
 * guidance, references, and any Top 10 tags copied into the bundled catalogue.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class WstgTest {

    private String id;
    private String name;
    private List<String> objectives;
    private String howToTest;
    private List<String> references;
    private List<String> owaspTop10Ids;

    public WstgTest() {}

    public WstgTest(
            String id,
            String name,
            List<String> objectives,
            String howToTest,
            List<String> references) {
        this.id = id;
        this.name = name;
        this.objectives = objectives;
        this.howToTest = howToTest;
        this.references = references;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public List<String> getObjectives() {
        return objectives;
    }

    public void setObjectives(List<String> objectives) {
        this.objectives = objectives;
    }

    public String getHowToTest() {
        return howToTest;
    }

    public void setHowToTest(String howToTest) {
        this.howToTest = howToTest;
    }

    public List<String> getReferences() {
        return references;
    }

    public void setReferences(List<String> references) {
        this.references = references;
    }

    /**
     * Accepts a single URL string from JSON format that uses {@code "reference"} instead of {@code
     * "references"}.
     */
    public void setReference(String reference) {
        if (reference != null && !reference.isBlank()) {
            this.references = List.of(reference);
        }
    }

    /**
     * Returns the OWASP Top 10 2025 category IDs that this test addresses (e.g. {@code ["A01:2025",
     * "A03:2025"]}), or {@code null} / empty if no mapping exists.
     */
    public List<String> getOwaspTop10Ids() {
        return owaspTop10Ids;
    }

    public void setOwaspTop10Ids(List<String> owaspTop10Ids) {
        this.owaspTop10Ids = owaspTop10Ids;
    }

    @Override
    public String toString() {
        return id + ": " + name;
    }
}
