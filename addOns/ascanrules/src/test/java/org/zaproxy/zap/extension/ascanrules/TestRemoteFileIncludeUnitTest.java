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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.zaproxy.zap.extension.ascanrules.utils.Constants.NULL_BYTE_CHARACTER;

import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/** Unit test for {@link TestRemoteFileInclude}. */
public class TestRemoteFileIncludeUnitTest
        extends ActiveScannerAppParamTest<TestRemoteFileInclude> {

    @Override
    protected TestRemoteFileInclude createScanner() {
        TestRemoteFileInclude scanner = new TestRemoteFileInclude();
        scanner.setConfig(new ZapXmlConfiguration());
        return scanner;
    }

    @Test
    public void shouldRaiseAlertIfResponseHasRemoteFileContentAndPayloadIsNullByteBased()
            throws HttpMalformedHeaderException {
        // Given
        NullByteVulnerableServerHandler vulnServerHandler =
                new NullByteVulnerableServerHandler("/", "p", Tech.Linux) {
                    @Override
                    protected String getContent(IHTTPSession session) {
                        String value = getFirstParamValue(session, "p");
                        if (value.contains(NULL_BYTE_CHARACTER)) {
                            return "<html><title>Google</title></html>";
                        } else {
                            return "<html></html>";
                        }
                    }
                };
        nano.addHandler(vulnServerHandler);
        rule.init(getHttpMessage("/?p=a"), parent);
        rule.setAttackStrength(AttackStrength.INSANE);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
    }
}
