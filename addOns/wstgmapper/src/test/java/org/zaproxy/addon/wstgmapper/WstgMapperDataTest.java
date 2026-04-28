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
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

import java.io.IOException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zaproxy.addon.wstgmapper.model.WstgTest;

/**
 * Unit tests for {@link WstgMapperData}.
 *
 * <p>These are sanity checks for the bundled WSTG catalogue and its lookup index, helping catch
 * broken resources or malformed JSON early in the build.
 */
class WstgMapperDataTest {

    private WstgMapperData data;

    @BeforeEach
    void setUp() throws IOException {
        data = new WstgMapperData();
    }

    @Test
    void loadsWithoutException() {
        // setUp() instantiates without throwing — reaching this point is enough.
    }

    @Test
    void categoriesAreNotEmpty() {
        assertThat(data.getCategories(), is(not(empty())));
    }

    @Test
    void testByIdMapIsNotEmpty() {
        assertThat(data.getTestById().entrySet(), is(not(empty())));
    }

    @Test
    void getTestReturnsNonNullForKnownId() {
        // WSTG-INFO-01 is the first test in the bundled JSON resource.
        WstgTest test = data.getTest("WSTG-INFO-01");

        assertThat(test, is(notNullValue()));
    }

    @Test
    void getTestReturnsTestWithCorrectId() {
        WstgTest test = data.getTest("WSTG-INFO-01");

        assertThat(test.getId(), is("WSTG-INFO-01"));
    }

    @Test
    void getTestReturnsNonBlankName() {
        WstgTest test = data.getTest("WSTG-INFO-01");

        assertThat(test.getName(), is(not("")));
    }

    @Test
    void getTestReturnsNullForUnknownId() {
        assertThat(data.getTest("WSTG-DOES-NOT-EXIST-999"), is(nullValue()));
    }

    @Test
    void allCategoriesHaveAtLeastOneTest() {
        data.getCategories()
                .forEach(
                        cat ->
                                assertThat(
                                        "Category " + cat.getId() + " has no tests",
                                        cat.getTests(),
                                        is(not(empty()))));
    }

    @Test
    void everyTestHasNonBlankId() {
        data.getTestById()
                .values()
                .forEach(
                        test -> assertThat("Test has blank id", test.getId().isBlank(), is(false)));
    }

    @Test
    void everyTestHasNonBlankName() {
        data.getTestById()
                .values()
                .forEach(
                        test ->
                                assertThat(
                                        "Test " + test.getId() + " has blank name",
                                        test.getName().isBlank(),
                                        is(false)));
    }
}
