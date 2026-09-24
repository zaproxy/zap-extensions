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
package org.zaproxy.addon.dev.auth.multiStepAuth;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;

/** Unit test for the redirect-to-login behaviour of {@link MultiStepAuthHomePage}. */
class MultiStepAuthHomePageUnitTest {

    @Test
    void shouldRedirectToLoginWhenNoCookiePresent() throws Exception {
        MultiStepAuthDir mockDir = mock(MultiStepAuthDir.class);
        MultiStepAuthHomePage page = createPage(mockDir);
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://localhost/home HTTP/1.1");

        page.handleMessage(null, msg);

        assertThat(msg.getResponseHeader().getStatusCode(), is(302));
        assertThat(msg.getResponseHeader().getHeader(HttpHeader.LOCATION), equalTo("index.html"));
    }

    @Test
    void shouldRedirectToLoginWhenSessionTokenIsInvalid() throws Exception {
        MultiStepAuthDir mockDir = mock(MultiStepAuthDir.class);
        given(mockDir.getUser(anyString())).willReturn(null);
        MultiStepAuthHomePage page = createPage(mockDir);
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://localhost/home HTTP/1.1");
        msg.getRequestHeader().setHeader(HttpHeader.COOKIE, "session=unknowntoken");

        page.handleMessage(null, msg);

        assertThat(msg.getResponseHeader().getStatusCode(), is(302));
        assertThat(msg.getResponseHeader().getHeader(HttpHeader.LOCATION), equalTo("index.html"));
    }

    private static MultiStepAuthHomePage createPage(MultiStepAuthDir parent) {
        return new MultiStepAuthHomePage(null) {
            @Override
            public MultiStepAuthDir getParent() {
                return parent;
            }
        };
    }
}
