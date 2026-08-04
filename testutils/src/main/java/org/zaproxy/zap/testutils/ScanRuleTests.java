/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.zap.testutils;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.emptyOrNullString;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.DynamicTest.dynamicTest;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.ResourceBundle;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Function;
import java.util.stream.Stream;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin;
import org.zaproxy.zap.extension.alert.ExampleAlertProvider;

interface ScanRuleTests extends UrlTests {

    Object getScanRule();

    @TestFactory
    default Collection<DynamicTest> addScanRuleTests() {
        List<DynamicTest> tests = new ArrayList<>();
        tests.add(dynamicTest("shouldHaveValidReferences", this::shouldHaveValidReferences));
        tests.add(
                dynamicTest(
                        "shouldHaveExpectedAlertRefsInExampleAlerts",
                        this::shouldHaveExpectedAlertRefsInExampleAlerts));
        return tests;
    }

    default void shouldHaveI18nNonEmptyName(String name, ResourceBundle extensionResourceBundle) {
        assertThat(name, is(not(emptyOrNullString())));
        assertThat(
                "Name does not seem to be i18n'ed, not found in the resource bundle:" + name,
                extensionResourceBundle.keySet().stream()
                        .map(extensionResourceBundle::getString)
                        .anyMatch(str -> str.equals(name)));
    }

    default void shouldHaveExpectedAlertRefsInExampleAlerts() {
        // Given / When
        List<Alert> alerts = getExampleAlerts(getScanRule());
        // Then
        if (alerts.size() <= 1) {
            return;
        }

        List<String> errors = new ArrayList<>();
        int i = 0;
        for (Alert alert : alerts) {
            ++i;
            String alertRef = alert.getPluginId() + "-" + i;
            if (!alertRef.equals(alert.getAlertRef())) {
                errors.add(
                        "Example Alert %s does not have expected ref: %s Has: %s"
                                .formatted(i, alertRef, alert.getAlertRef()));
            }
        }

        assertThat(errors.toString(), errors, is(empty()));
    }

    private static List<Alert> getExampleAlerts(Object scanRule) {
        if (scanRule instanceof ExampleAlertProvider eap) {
            return Optional.ofNullable(eap.getExampleAlerts()).orElse(List.of());
        }
        return List.of();
    }

    default void shouldHaveValidReferences() {
        shouldHaveValidUrls(getAllReferences(getScanRule()));
    }

    private static Set<String> getAllReferences(Object scanRule) {
        Set<String> references = new TreeSet<>();
        if (scanRule instanceof ExampleAlertProvider) {
            Optional.ofNullable(((ExampleAlertProvider) scanRule).getExampleAlerts())
                    .orElse(List.of())
                    .stream()
                    .map(Alert::getReference)
                    .map(ScanRuleTests::convertReferences)
                    .flatMap(Function.identity())
                    .forEach(references::add);
        }
        if (scanRule instanceof Plugin) {
            convertReferences(((Plugin) scanRule).getReference()).forEach(references::add);
        }

        return references;
    }

    private static Stream<String> convertReferences(String refs) {
        return Arrays.stream(Optional.ofNullable(refs).orElse("").split("\\r?\\n"))
                .map(String::trim)
                .filter(e -> !e.isEmpty());
    }
}
