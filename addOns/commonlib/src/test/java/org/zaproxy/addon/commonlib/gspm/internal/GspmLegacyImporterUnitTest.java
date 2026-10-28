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
package org.zaproxy.addon.commonlib.gspm.internal;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.commonlib.ExtensionCommonlib;
import org.zaproxy.addon.commonlib.gspm.GspmPolicy;
import org.zaproxy.addon.commonlib.gspm.GspmRuleRef;
import org.zaproxy.addon.commonlib.gspm.GspmRuleSet;
import org.zaproxy.zap.testutils.TestUtils;

class GspmLegacyImporterUnitTest extends TestUtils {

    @BeforeAll
    static void setupMessages() {
        // GspmPolicy.nextDefaultRuleSetName(), used to name imported per-rule-override groups,
        // reads Constant.messages.
        mockMessages(new ExtensionCommonlib());
    }

    @AfterAll
    static void cleanUpMessages() {
        Constant.messages = null;
    }

    private static final String POLICY_XML =
            """
            <configuration>
              <policy>My Policy</policy>
              <scanner>
                <level>MEDIUM</level>
                <strength>MEDIUM</strength>
              </scanner>
              <locked>false</locked>
              <plugins>
                <p40012>
                  <name>Cross Site Scripting (Reflected)</name>
                  <enabled>true</enabled>
                  <level>HIGH</level>
                </p40012>
                <p90001>
                  <enabled>true</enabled>
                  <level>HIGH</level>
                </p90001>
              </plugins>
            </configuration>
            """;

    @Test
    void shouldPreserveRuleNameFromFileWhenPresent(@TempDir Path dir) throws Exception {
        // Given
        Path file = dir.resolve("My Policy.policy");
        Files.writeString(file, POLICY_XML);

        // When
        GspmPolicy policy = GspmLegacyImporter.importPolicy(file.toFile());

        // Then
        GspmRuleRef ref = findRuleRef(policy, 40012);
        assertThat(ref.getName(), is("Cross Site Scripting (Reflected)"));
    }

    @Test
    void shouldStoreNullNameWhenNotPresentInFile(@TempDir Path dir) throws Exception {
        // Given
        Path file = dir.resolve("My Policy.policy");
        Files.writeString(file, POLICY_XML);

        // When — rule 90001 has no <name> element in the file
        GspmPolicy policy = GspmLegacyImporter.importPolicy(file.toFile());

        // Then
        GspmRuleRef ref = findRuleRef(policy, 90001);
        assertThat(ref.getName(), is(nullValue()));
    }

    @Test
    void shouldAssignDefaultNameToPerRuleOverrideGroup(@TempDir Path dir) throws Exception {
        // Given — both p40012 and p90001 override to HIGH (default is MEDIUM), so they land in
        // the same per-rule-override group, which has no name of its own from the legacy XML.
        Path file = dir.resolve("My Policy.policy");
        Files.writeString(file, POLICY_XML);

        // When
        GspmPolicy policy = GspmLegacyImporter.importPolicy(file.toFile());

        // Then
        GspmRuleSet group = ruleSetFor(policy, 40012);
        assertThat(group, is(ruleSetFor(policy, 90001)));
        assertThat(group.getName(), is("Rule Set 1"));
    }

    private static GspmRuleSet ruleSetFor(GspmPolicy policy, int ruleId) {
        for (GspmRuleSet ruleSet : policy.getRuleSets()) {
            List<GspmRuleRef> rules = ruleSet.getRules();
            if (rules == null) {
                continue;
            }
            for (GspmRuleRef ref : rules) {
                if (ref.getId() == ruleId) {
                    return ruleSet;
                }
            }
        }
        throw new AssertionError("No rule set found containing rule id " + ruleId);
    }

    private static GspmRuleRef findRuleRef(GspmPolicy policy, int ruleId) {
        for (GspmRuleSet ruleSet : policy.getRuleSets()) {
            List<GspmRuleRef> rules = ruleSet.getRules();
            if (rules == null) {
                continue;
            }
            for (GspmRuleRef ref : rules) {
                if (ref.getId() == ruleId) {
                    return ref;
                }
            }
        }
        throw new AssertionError("No rule ref found for id " + ruleId);
    }
}
