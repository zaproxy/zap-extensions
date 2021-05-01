/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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
package org.zaproxy.zap.extension.ascanrules;

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

import fi.iki.elonen.NanoHTTPD;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.testutils.NanoServerHandler;

/** Unit test for {@link DirectoryBrowsingScanRule}. */
public class DirectoryBrowsingScanRuleUnitTest
        extends ActiveScannerTest<DirectoryBrowsingScanRule> {
    private static final String RESOURCES_FOLDER =
            "/org/zaproxy/zap/extension/ascanrules/directorybrowsingscanrule/";

    @Override
    protected DirectoryBrowsingScanRule createScanner() {
        return new DirectoryBrowsingScanRule();
    }

    @Test
    public void shouldFindDirectoryListing() throws Exception {
        // Given
        String test = "/";
        this.nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected NanoHTTPD.Response serve(NanoHTTPD.IHTTPSession session) {
                        String html = getHtml(RESOURCES_FOLDER + "DirectoryListing.html");
                        return newFixedLengthResponse(html);
                    }
                });
        // When
        HttpMessage msg = this.getHttpMessage(test);
        this.rule.init(msg, this.parent);
        this.rule.scan();
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo("Parent Directory"));
    }
}
