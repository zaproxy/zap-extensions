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

import java.util.List;

/**
 * Simple model object for one WSTG category and the tests it contains.
 *
 * <p>Instances are populated from the bundled JSON and reused by the UI, coverage calculator, and
 * exporters as the grouped structure of the checklist.
 */
public class WstgCategory {

    private String id;
    private String name;
    private List<WstgTest> tests;

    public WstgCategory() {}

    public WstgCategory(String id, String name, List<WstgTest> tests) {
        this.id = id;
        this.name = name;
        this.tests = tests;
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

    public List<WstgTest> getTests() {
        return tests;
    }

    public void setTests(List<WstgTest> tests) {
        this.tests = tests;
    }
}
