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
package org.zaproxy.addon.authhelper;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.utils.I18N;

/** Unit test for the method-id/label persistence helpers in {@link AuthTestDialog}. */
class AuthTestDialogUnitTest {

    private static final String BROWSER_LABEL = "Browser Based";
    private static final String SCRIPT_LABEL = "Client Script Based";
    private static final String AI_LABEL = "AI Assisted";

    @BeforeAll
    static void beforeAll() {
        Constant.messages = mock(I18N.class);
        given(Constant.messages.getString("authhelper.auth.test.dialog.label.method.browser"))
                .willReturn(BROWSER_LABEL);
        given(Constant.messages.getString("authhelper.auth.test.dialog.label.method.script"))
                .willReturn(SCRIPT_LABEL);
        given(Constant.messages.getString("authhelper.auth.test.dialog.label.method.ai"))
                .willReturn(AI_LABEL);
        given(Constant.messages.getString("authhelper.auth.test.dialog.results.found"))
                .willReturn("Found");
    }

    @AfterAll
    static void afterAll() {
        Constant.messages = null;
    }

    @Test
    void shouldMapScriptIdToScriptLabelWhenSupported() {
        assertThat(AuthTestDialog.methodIdToLabel("script", true, true), is(equalTo(SCRIPT_LABEL)));
    }

    @Test
    void shouldMapAiIdToAiLabelWhenSupported() {
        assertThat(AuthTestDialog.methodIdToLabel("ai", true, true), is(equalTo(AI_LABEL)));
    }

    @Test
    void shouldFallBackToBrowserWhenScriptIdNotSupported() {
        assertThat(
                AuthTestDialog.methodIdToLabel("script", false, true), is(equalTo(BROWSER_LABEL)));
    }

    @Test
    void shouldFallBackToBrowserWhenAiIdNotSupported() {
        assertThat(AuthTestDialog.methodIdToLabel("ai", true, false), is(equalTo(BROWSER_LABEL)));
    }

    @Test
    void shouldFallBackToBrowserForUnknownId() {
        assertThat(
                AuthTestDialog.methodIdToLabel("unknown", true, true), is(equalTo(BROWSER_LABEL)));
    }

    @Test
    void shouldMapLabelsBackToTheirIds() {
        assertThat(AuthTestDialog.methodLabelToId(BROWSER_LABEL), is(equalTo("browser")));
        assertThat(AuthTestDialog.methodLabelToId(SCRIPT_LABEL), is(equalTo("script")));
        assertThat(AuthTestDialog.methodLabelToId(AI_LABEL), is(equalTo("ai")));
    }

    @Test
    void shouldMapUnknownLabelToBrowserId() {
        assertThat(AuthTestDialog.methodLabelToId("something else"), is(equalTo("browser")));
    }
}
