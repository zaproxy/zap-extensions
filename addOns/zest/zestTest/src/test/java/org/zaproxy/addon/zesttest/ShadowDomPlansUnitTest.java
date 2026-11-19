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
package org.zaproxy.addon.zesttest;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.equalTo;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLMapper;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.zaproxy.addon.zesttest.shadowdom.ShadowDomAction;
import org.zaproxy.addon.zesttest.shadowdom.ShadowDomCase;

/** Checks the Automation Framework plans of the Shadow DOM cases match the test app. */
class ShadowDomPlansUnitTest {

    private static final String PLANS_DIR = "src/main/zapHomeFiles/integration-tests/zest/plans/";
    private static final String BASE_URL = "http://localhost:9091/zest/shadow-dom/";

    @ParameterizedTest
    @EnumSource(ShadowDomCase.class)
    void shouldHavePlanWithZestScriptForCase(ShadowDomCase shadowDomCase) throws Exception {
        // Given
        JsonNode plan = readPlan(shadowDomCase);
        JsonNode jobs = plan.get("jobs");
        // When
        JsonNode script =
                new ObjectMapper().readTree(jobs.get(0).at("/parameters/inline").asText());
        // Then
        String caseUrl = BASE_URL + shadowDomCase.getDirName() + "/";
        JsonNode statements = script.get("statements");
        assertThat(statements.get(0).get("elementType").asText(), equalTo("ZestClientLaunch"));
        assertThat(statements.get(0).get("url").asText(), equalTo(caseUrl));
        List<String> elements = new ArrayList<>();
        for (JsonNode statement : statements) {
            if (statement.has("element")) {
                elements.add(statement.get("element").asText());
                assertThat(statement.get("type").asText(), equalTo("cssSelector"));
                assertThat(
                        toList(statement.get("shadowPath")),
                        equalTo(shadowDomCase.getShadowPath()));
            } else if (statement.has("url")) {
                assertThat(statement.get("url").asText(), equalTo(caseUrl));
            }
        }
        assertThat(elements, contains("#link", "#button", "#input", "#input"));
        assertThat(
                jobs.get(1).at("/parameters/name").asText(),
                equalTo(jobs.get(0).at("/parameters/name").asText()));
    }

    @ParameterizedTest
    @EnumSource(ShadowDomCase.class)
    void shouldHaveUrlTestPerAction(ShadowDomCase shadowDomCase) throws Exception {
        // Given
        JsonNode tests = readPlan(shadowDomCase).get("jobs").get(1).get("tests");
        String caseUrl = BASE_URL + shadowDomCase.getDirName() + "/";
        // When
        List<String> urls = new ArrayList<>();
        for (JsonNode test : tests) {
            assertThat(test.get("type").asText(), equalTo("url"));
            urls.add(test.get("url").asText());
        }
        // Then
        assertThat(
                urls,
                containsInAnyOrder(
                        caseUrl + ShadowDomAction.LINK.getPageName(),
                        caseUrl + ShadowDomAction.BUTTON.getPageName(),
                        caseUrl + ShadowDomAction.FORM.getPageName() + "?value=zest"));
    }

    private static JsonNode readPlan(ShadowDomCase shadowDomCase) throws Exception {
        return new YAMLMapper()
                .readTree(
                        Files.readString(
                                Path.of(
                                        PLANS_DIR,
                                        "shadow-dom-" + shadowDomCase.getDirName() + ".yaml")));
    }

    private static List<String> toList(JsonNode array) {
        List<String> values = new ArrayList<>();
        array.forEach(e -> values.add(e.asText()));
        return values;
    }
}
