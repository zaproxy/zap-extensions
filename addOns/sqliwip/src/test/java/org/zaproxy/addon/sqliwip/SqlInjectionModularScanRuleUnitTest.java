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
package org.zaproxy.addon.sqliwip;

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.junit.jupiter.api.Assertions.assertEquals;

import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.zaproxy.zap.testutils.NanoServerHandler;

/** Unit test for {@link SqlInjectionModularScanRule}. */
class SqlInjectionModularScanRuleUnitTest extends AbstractSqlInjectionModularScanRuleTest {

    @Test
    void shouldHaveTemporaryId() {
        assertEquals(424242, rule.getId());
    }

    @Test
    void shouldSendNoRequestsWithoutStrategies() throws Exception {
        // Given
        String path = "/";
        nano.addHandler(
                new NanoServerHandler(path) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        return newFixedLengthResponse("<html></html>");
                    }
                });
        rule.setAttackStrength(AttackStrength.INSANE);
        // When
        rule.init(getHttpMessage(path + "?id=1"), parent);
        rule.scan();
        // Then
        assertEquals(0, countMessagesSent);
    }
}
