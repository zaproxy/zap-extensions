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
package org.zaproxy.addon.reports;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

import org.junit.jupiter.api.Test;

class ReportOutputOptionsUnitTest {

    @Test
    void shouldDisableDisplayWhenZipSelected() {
        assertThat(ReportOutputOptions.resolveDisplay(true, true), is(false));
        assertThat(ReportOutputOptions.resolveDisplay(true, false), is(false));
    }

    @Test
    void shouldKeepDisplayWhenZipNotSelected() {
        assertThat(ReportOutputOptions.resolveDisplay(false, true), is(true));
        assertThat(ReportOutputOptions.resolveDisplay(false, false), is(false));
    }

    @Test
    void shouldPreferZipWhenBothEnabled() {
        assertThat(ReportOutputOptions.bothEnabled(true, true), is(true));
        assertThat(ReportOutputOptions.bothEnabled(true, false), is(false));
        assertThat(ReportOutputOptions.bothEnabled(false, true), is(false));
    }

    @Test
    void shouldPreferZipWhenBothInitiallySelected() {
        boolean[] resolved = ReportOutputOptions.resolveInitialSelection(true, true);

        assertThat(resolved[0], is(true));
        assertThat(resolved[1], is(false));
    }
}
