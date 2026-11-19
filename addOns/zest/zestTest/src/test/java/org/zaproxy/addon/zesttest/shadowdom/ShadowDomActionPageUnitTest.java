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
package org.zaproxy.addon.zesttest.shadowdom;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;

import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMessage;

/** Unit test for {@link ShadowDomActionPage}. */
class ShadowDomActionPageUnitTest {

    @Test
    void shouldCreateBodyWithCaseAndAction() {
        // Given / When
        String body =
                ShadowDomActionPage.createBody(ShadowDomCase.OPEN, ShadowDomAction.LINK, null);
        // Then
        assertThat(body, containsString("<p id=\"result\">open link OK</p>"));
        assertThat(body, not(containsString("id=\"value\"")));
    }

    @Test
    void shouldCreateBodyWithEscapedValue() {
        // Given / When
        String body =
                ShadowDomActionPage.createBody(
                        ShadowDomCase.CLOSED, ShadowDomAction.FORM, "<b>&\"");
        // Then
        assertThat(body, containsString("<p id=\"result\">closed form OK</p>"));
        assertThat(body, containsString("<p id=\"value\">&lt;b&gt;&amp;&quot;</p>"));
    }

    @Test
    void shouldHandleMessageWithValueFromQuery() throws Exception {
        // Given
        ShadowDomDir dir = new ShadowDomDir(null, ShadowDomCase.OPEN_OPEN);
        ShadowDomActionPage page = new ShadowDomActionPage(null, ShadowDomAction.FORM);
        dir.addPage(page);
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(
                "GET http://localhost/zest/shadow-dom/open-open/form?value=zest HTTP/1.1");
        // When
        page.handleMessage(null, msg);
        // Then
        assertThat(msg.getResponseHeader().toString(), containsString("200 OK"));
        assertThat(msg.getResponseBody().toString(), containsString("open-open form OK"));
        assertThat(msg.getResponseBody().toString(), containsString("<p id=\"value\">zest</p>"));
    }
}
