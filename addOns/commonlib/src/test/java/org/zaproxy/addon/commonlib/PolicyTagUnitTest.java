/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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
package org.zaproxy.addon.commonlib;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.endsWith;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.in;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.startsWith;
import static org.hamcrest.core.DescribedAs.describedAs;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

class PolicyTagUnitTest {

    private static final String FILE_EXT = ".policy";
    private static final List<String> CURRENT_ADDONS = List.of("scanpolicies", "sequence");

    @ParameterizedTest
    @EnumSource(PolicyTag.class)
    void shouldHaveAllTagsStartingWithPolicyyUnderscoreInCapsEnumNamesWithout(PolicyTag tag) {
        // Given / When / Then
        assertThat(
                tag.name(),
                describedAs(
                        "Enum element name should not start with prefix",
                        not(startsWith(PolicyTag.PREFIX))));
        assertThat(
                tag.getTag(),
                describedAs(
                        "Tag should start with expected prefix", is(startsWith(PolicyTag.PREFIX))));
        assertThat(
                tag.getFileName(),
                describedAs(
                        "Enum filenames should all end with '.policy'", is(endsWith(FILE_EXT))));
        assertThat(
                tag.getAddonId(),
                describedAs(
                        "Enum values should be attributed to expected addons",
                        is(in(CURRENT_ADDONS))));
    }

    @Test
    void shouldHaveCompleteListWhenGettingAllTags() {
        // Given / When
        List<String> tags = PolicyTag.getAllTags();
        // Then
        assertThat(PolicyTag.values().length, is(equalTo(tags.size())));
    }
}
