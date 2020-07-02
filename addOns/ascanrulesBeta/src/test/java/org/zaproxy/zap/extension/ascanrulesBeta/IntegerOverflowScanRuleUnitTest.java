/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP Development Team
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
package org.zaproxy.zap.extension.ascanrulesBeta;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;

import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;

/** Unit test for {@link IntegerOverflowScanRule}. */
public class IntegerOverflowScanRuleUnitTest extends ActiveScannerTest<IntegerOverflowScanRule> {

    @Override
    protected IntegerOverflowScanRule createScanner() {
        return new IntegerOverflowScanRule();
    }

    @Test
    public void shouldTargetCTech() {
        // Given
        TechSet techSet = techSet(Tech.C);
        // When
        boolean targets = rule.targets(techSet);
        // Then
        assertThat(targets, is(equalTo(true)));
    }

    @Test
    public void shouldNotTargetNonCTechs() {
        // Given
        TechSet techSet = techSetWithout(Tech.C);
        // When
        boolean targets = rule.targets(techSet);
        // Then
        assertThat(targets, is(equalTo(false)));
    }

    @Test
    public void shouldSkipScanning500ErrorMessage() throws Exception {
        // Given
        HttpMessage message = getHttpMessage("?param=value");
        message.setResponseHeader(
                "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n");
        rule.init(message, parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, is(empty()));
    }

    @Test
    public void shouldScanNon500ErrorMessage() throws Exception {
        // Given
        rule.init(getHttpMessage("?param=value"), parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, is(not(empty())));
    }

    @Test
    public void shouldSkipScanIfStopped() throws Exception {
        // Given
        rule.init(getHttpMessage("?param=value"), parent);
        parent.stop();
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, is(empty()));
    }
}
