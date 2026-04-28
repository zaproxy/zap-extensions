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

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;
import org.zaproxy.addon.wstgmapper.model.WstgCategory;
import org.zaproxy.addon.wstgmapper.model.WstgTest;

/**
 * Resolves detected technologies to the WSTG tests and categories they make relevant.
 *
 * <p>The panel uses this helper to narrow the checklist when technology fingerprints suggest which
 * parts of the guide matter most for the current target.
 */
public class TechStackDetector {

    private final WstgMapperMappingManager mappingManager;
    private final WstgMapperData data;

    public TechStackDetector(WstgMapperMappingManager mappingManager, WstgMapperData data) {
        this.mappingManager = mappingManager;
        this.data = data;
    }

    public Set<String> getRelevantTestIds(WstgMapperChecklistManager checklistManager) {
        Set<String> relevantTests = new LinkedHashSet<>();
        for (String technology : checklistManager.getDetectedTechnologies()) {
            relevantTests.addAll(mappingManager.getWstgIdsForTechnology(technology));
        }
        return Collections.unmodifiableSet(relevantTests);
    }

    public Set<String> getRelevantCategoryIds(WstgMapperChecklistManager checklistManager) {
        Set<String> relevantTests = getRelevantTestIds(checklistManager);
        Set<String> relevantCategories = new LinkedHashSet<>();
        for (WstgCategory category : data.getCategories()) {
            if (category.getTests() == null) {
                continue;
            }
            for (WstgTest test : category.getTests()) {
                if (relevantTests.contains(test.getId())) {
                    relevantCategories.add(category.getId());
                    break;
                }
            }
        }
        return Collections.unmodifiableSet(relevantCategories);
    }
}
