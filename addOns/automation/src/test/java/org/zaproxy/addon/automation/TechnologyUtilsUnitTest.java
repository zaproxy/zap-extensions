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
package org.zaproxy.addon.automation;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;
import org.zaproxy.zap.utils.I18N;

class TechnologyUtilsUnitTest {

    static Tech Db_A = new Tech(Tech.Db, "Db_A");
    static Tech Db_B = new Tech(Tech.Db, "Db_B");
    static Tech Db_C = new Tech(Tech.Db, "Db_C");
    static Tech Lang_A = new Tech(Tech.Lang, "Lang_A");
    static Tech Lang_B = new Tech(Tech.Lang, "Lang_B");
    static Tech Lang_C = new Tech(Tech.Lang, "Lang_C");
    static Tech Lang_C_A = new Tech(Lang_C, "Lang_C_A");
    static Tech Lang_C_B = new Tech(Lang_C, "Lang_C_B");

    static final TreeSet<Tech> testTech =
            new TreeSet<>(
                    Arrays.asList(
                            Tech.Db, Db_A, Db_B, Db_C, Tech.Lang, Lang_A, Lang_B, Lang_C, Lang_C_A,
                            Lang_C_B));

    @Test
    void shouldExcludeNothingForAllTech() {
        // Given / When
        Set<Tech> set = TechnologyUtils.getFilteredExludeTech(testTech, new HashSet<>());

        // Then
        assertThat(set.size(), is(equalTo(0)));
    }

    @Test
    void shouldExcludeSingleLevel1Tech() {
        // Given
        Set<Tech> incSet = new HashSet<>(testTech);
        incSet.remove(Tech.Db);
        incSet.remove(Db_B);
        Set<Tech> excSet = new HashSet<>();
        excSet.add(Tech.Db);
        excSet.add(Db_B);

        // When
        Set<Tech> set = TechnologyUtils.getFilteredExludeTech(incSet, excSet);

        // Then
        assertThat(set.size(), is(equalTo(1)));
        assertThat(set.contains(Db_B), is(equalTo(true)));
    }

    @Test
    void shouldExcludeSingleLevel2Techs() {
        // Given
        Set<Tech> incSet = new HashSet<>(testTech);
        incSet.remove(Tech.Lang);
        incSet.remove(Lang_A);
        incSet.remove(Lang_B);
        Set<Tech> excSet = new HashSet<>();
        excSet.add(Tech.Lang);
        excSet.add(Lang_A);
        excSet.add(Lang_B);

        // When
        Set<Tech> set = TechnologyUtils.getFilteredExludeTech(incSet, excSet);

        // Then
        assertThat(set.size(), is(equalTo(2)));
        assertThat(set.contains(Lang_A), is(equalTo(true)));
        assertThat(set.contains(Lang_B), is(equalTo(true)));
    }

    @Test
    void shouldExcludeMultiLevel1Tech() {
        // Given
        Set<Tech> incSet = new HashSet<>(testTech);
        incSet.remove(Tech.Lang);
        incSet.remove(Lang_C);
        incSet.remove(Lang_C_B);
        Set<Tech> excSet = new HashSet<>();
        excSet.add(Tech.Lang);
        excSet.add(Lang_C);
        excSet.add(Lang_C_B);

        // When
        Set<Tech> set = TechnologyUtils.getFilteredExludeTech(incSet, excSet);

        // Then
        assertThat(set.size(), is(equalTo(1)));
        assertThat(set.contains(Lang_C_B), is(equalTo(true)));
    }

    @Test
    void shouldExcludeWholeSubtree() {
        // Given
        Set<Tech> incSet = new HashSet<>(testTech);
        incSet.remove(Tech.Db);
        incSet.remove(Db_A);
        incSet.remove(Db_B);
        incSet.remove(Db_C);
        Set<Tech> excSet = new HashSet<>();
        excSet.add(Tech.Db);
        excSet.add(Db_A);
        excSet.add(Db_B);
        excSet.add(Db_C);

        // When
        Set<Tech> set = TechnologyUtils.getFilteredExludeTech(incSet, excSet);

        // Then
        assertThat(set.size(), is(equalTo(1)));
        assertThat(set.contains(Tech.Db), is(equalTo(true)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"Lang_C", "Lang_C_B"})
    void shouldReportParentInSet(String name) {
        // Given / When
        Constant.messages = new I18N(Locale.ENGLISH);
        AutomationProgress progress = new AutomationProgress();

        // Then
        assertThat(
                TechnologyUtils.parentInSet(
                        testTech, TechnologyUtils.getTech(testTech, name, progress)),
                is(equalTo(true)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"Language", "BadTech"})
    void shouldReportParentNotInSet(String name) {
        // Given / When
        Constant.messages = new I18N(Locale.ENGLISH);
        AutomationProgress progress = new AutomationProgress();

        // Then
        assertThat(
                TechnologyUtils.parentInSet(
                        testTech, TechnologyUtils.getTech(testTech, name, progress)),
                is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }

    @ParameterizedTest
    @CsvSource({"db_a,db", "Lang_A,LANGUAGE", "LANG_C_A,lang_c"})
    void shouldReportChildHasParent(String child, String parent) {
        // Given / When
        Constant.messages = new I18N(Locale.ENGLISH);
        AutomationProgress progress = new AutomationProgress();

        // When
        assertThat(
                TechnologyUtils.childHasParent(
                        TechnologyUtils.getTech(testTech, child, progress),
                        TechnologyUtils.getTech(testTech, parent, progress)),
                is(equalTo(true)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }

    @ParameterizedTest
    @CsvSource({
        "db_a,language",
        "lang_c,db",
        "lang_C,LANG_C_A",
        "LANG_C_A,BadTech",
        "BadTech,lang_c",
        "BadTech1,BadTech2"
    })
    void shouldReportChildDoesNotHaveParent(String child, String parent) {
        // Given / When
        Constant.messages = new I18N(Locale.ENGLISH);
        AutomationProgress progress = new AutomationProgress();

        // When
        assertThat(
                TechnologyUtils.childHasParent(
                        TechnologyUtils.getTech(child, progress),
                        TechnologyUtils.getTech(parent, progress)),
                is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }

    @Test
    void shouldRemoveLevel1FromSet() {
        // Given
        TechSet set = new TechSet(testTech);
        int count = set.getIncludeTech().size();

        // When
        TechnologyUtils.removeTechAndParents(set, Tech.Db);

        // Then
        assertThat(set.getIncludeTech().size(), is(equalTo(count - 1)));
        assertThat(set.includes(Tech.Db), is(equalTo(false)));
    }

    @Test
    void shouldRemoveLevel2AndParentsFromSet() {
        // Given
        TechSet set = new TechSet(testTech);
        int count = set.getIncludeTech().size();

        // When
        TechnologyUtils.removeTechAndParents(set, Db_A);

        // Then
        assertThat(set.getIncludeTech().size(), is(equalTo(count - 2)));
        assertThat(set.includes(Db_A), is(equalTo(false)));
        assertThat(set.includes(Tech.Db), is(equalTo(false)));
    }

    @Test
    void shouldRemoveLevel3AndParentsFromSet() {
        // Given
        TechSet set = new TechSet(testTech);
        int count = set.getIncludeTech().size();

        // When
        TechnologyUtils.removeTechAndParents(set, Lang_C_B);

        // Then
        assertThat(set.getIncludeTech().size(), is(equalTo(count - 3)));
        assertThat(set.includes(Lang_C_B), is(equalTo(false)));
        assertThat(set.includes(Lang_C), is(equalTo(false)));
        assertThat(set.includes(Tech.Lang), is(equalTo(false)));
    }

    @Test
    void shouldRemoveLevel1FromTechSet() {
        // Given
        TechSet set = new TechSet(testTech);
        int count = set.getIncludeTech().size();

        // When
        TechnologyUtils.removeTechAndParents(set, Tech.Db);

        // Then
        assertThat(set.getIncludeTech().size(), is(equalTo(count - 1)));
        assertThat(set.includes(Tech.Db), is(equalTo(false)));
    }

    @Test
    void shouldRemoveLevel2AndParentsFromTechSet() {
        // Given
        TechSet set = new TechSet(testTech);
        int count = set.getIncludeTech().size();

        // When
        TechnologyUtils.removeTechAndParents(set, Db_A);

        // Then
        assertThat(set.getIncludeTech().size(), is(equalTo(count - 2)));
        assertThat(set.includes(Db_A), is(equalTo(false)));
        assertThat(set.includes(Tech.Db), is(equalTo(false)));
    }

    @Test
    void shouldRemoveLevel3AndParentsFromTechSet() {
        // Given
        TechSet set = new TechSet(testTech);
        int count = set.getIncludeTech().size();

        // When
        TechnologyUtils.removeTechAndParents(set, Lang_C_B);

        // Then
        assertThat(set.getIncludeTech().size(), is(equalTo(count - 3)));
        assertThat(set.includes(Lang_C_B), is(equalTo(false)));
        assertThat(set.includes(Lang_C), is(equalTo(false)));
        assertThat(set.includes(Tech.Lang), is(equalTo(false)));
    }

    @Test
    void shouldReturnAllTechIfNullExcludesAndIncludes() {
        // Given
        TechnologyData source = new TechnologyData();

        // When
        TechSet set = TechnologyUtils.getTechSet(source);

        // Then
        assertThat(set.getIncludeTech().size(), is(equalTo(Tech.getAll().size())));
        assertThat(set.getExcludeTech().size(), is(equalTo(0)));
    }

    @Test
    void shouldReturnIncludedTechs() {
        // Given
        TechnologyData source =
                new TechnologyData(Map.of("include", List.of("Windows")), null, null);

        // When
        TechSet set = TechnologyUtils.getTechSet(source);

        // Then
        assertThat(set.getIncludeTech(), contains(Tech.Windows));
        assertThat(set.getExcludeTech(), is(empty()));
    }

    @Test
    void shouldReturnIncludedTechsWithExcludes() {
        // Given
        TechnologyData source =
                new TechnologyData(
                        Map.of("include", List.of("OS"), "exclude", List.of("Windows")),
                        null,
                        null);

        // When
        TechSet set = TechnologyUtils.getTechSet(source);

        // Then
        assertThat(set.getIncludeTech(), contains(Tech.OS, Tech.Linux, Tech.MacOS));
        assertThat(set.getExcludeTech(), contains(Tech.Windows));
    }

    @Test
    void shouldRemoveTechIfExcludes() {
        // Given
        TechnologyData source = new TechnologyData();
        source.setExclude(List.of(Tech.ASP.getName()));

        // When
        TechSet set = TechnologyUtils.getTechSet(source);

        // Then
        assertThat(set.getIncludeTech().size(), is(equalTo(Tech.getAll().size() - 1)));
        assertThat(set.getIncludeTech().contains(Tech.ASP), is(equalTo(false)));
        assertThat(set.getExcludeTech().size(), is(equalTo(1)));
    }

    @Test
    void shouldResetIncludeWhenSettingExclude() {
        // Given
        TechnologyData source =
                new TechnologyData(
                        Map.of("include", List.of("OS"), "exclude", List.of("Windows")),
                        null,
                        null);

        // When
        source.setExclude(List.of("C"));

        // Then
        assertThat(source.getInclude(), is(nullValue()));
        assertThat(source.getExclude(), contains("C"));
    }
}
