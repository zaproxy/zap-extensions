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
package org.zaproxy.zap.extension.zest.dialogs;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.zaproxy.zap.extension.zest.ExtensionZest;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit test for {@link ZestClientElementDialog}. */
class ZestClientElementDialogUnitTest extends TestUtils {

    @BeforeAll
    static void setUpAll() {
        mockMessages(new ExtensionZest());
    }

    @ParameterizedTest
    @ValueSource(strings = {"xpath", "id", "classname"})
    void shouldAcceptNoShadowPathWithAnyType(String type) {
        assertThat(ZestClientElementDialog.validateShadowPath(List.of(), type), is(nullValue()));
        assertThat(ZestClientElementDialog.validateShadowPath(null, type), is(nullValue()));
    }

    @Test
    void shouldAcceptShadowPathWithCssSelector() {
        assertThat(
                ZestClientElementDialog.validateShadowPath(List.of("#host"), "cssselector"),
                is(nullValue()));
    }

    @ParameterizedTest
    @ValueSource(strings = {"xpath", "id", "classname"})
    void shouldRejectShadowPathWithNonCssSelector(String type) {
        assertThat(
                ZestClientElementDialog.validateShadowPath(List.of("#host"), type),
                is(notNullValue()));
    }

    @Test
    void shouldRejectShadowPathWithoutType() {
        assertThat(
                ZestClientElementDialog.validateShadowPath(List.of("#host"), null),
                is(notNullValue()));
    }

    @Test
    void shouldConvertNoShadowPathToNull() {
        assertThat(ZestClientElementDialog.toShadowPath(List.of()), is(nullValue()));
        assertThat(ZestClientElementDialog.toShadowPath(null), is(nullValue()));
    }

    @Test
    void shouldConvertShadowPathToCopy() {
        List<String> values = List.of("#host", "div");
        assertThat(ZestClientElementDialog.toShadowPath(values), is(equalTo(values)));
    }
}
