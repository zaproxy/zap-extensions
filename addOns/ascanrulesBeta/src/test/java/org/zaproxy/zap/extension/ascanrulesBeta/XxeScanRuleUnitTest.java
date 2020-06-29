/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2019 The ZAP Development Team
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
import static org.hamcrest.Matchers.is;

import org.junit.jupiter.api.Test;

public class XxeScanRuleUnitTest extends ActiveScannerTest<XxeScanRule> {

    @Override
    protected XxeScanRule createScanner() {
        return new XxeScanRule();
    }

    @Test
    public void replaceElementAndRemoveHeader() {
        // Given
        String requestBody = "<?xml version=\"1.0\"?><comment><text>\ntest\n</text></comment>";
        // When
        String payload = XxeScanRule.createLfrPayload(requestBody);
        // Then
        String expectedPayload =
                XxeScanRule.ATTACK_HEADER + "<comment><text>&zapxxe;</text></comment>";
        assertThat(payload, is(expectedPayload));
    }

    @Test
    public void doNotReplaceAttributes() {
        // Given
        String requestBody =
                "<?xml version=\"1.0\"?><comment><text abc=\"123\">test</text></comment>";
        // When
        String payload = XxeScanRule.createLfrPayload(requestBody);
        // Then
        String expectedPayload =
                XxeScanRule.ATTACK_HEADER + "<comment><text abc=\"123\">&zapxxe;</text></comment>";
        assertThat(payload, is(expectedPayload));
    }

    @Test
    public void replaceMultipleElementsAndRemoveHeader() {
        // Given
        String requestBody =
                "\n"
                        + "<?xml version=\"1.0\"?>\n"
                        + "<comments>\n"
                        + "    <comment>\n"
                        + "    <text>test\n"
                        + "    </text>\n"
                        + "    </comment>\n"
                        + "\n"
                        + "    <comment>\n"
                        + "    <text>   test   </text>\n"
                        + "    </comment>\n"
                        + "    <comment>\n"
                        + "\n"
                        + "<otherValue>A</otherValue>\n"
                        + "<otherValue>B</otherValue>\n"
                        + "<otherValue>C</otherValue>\n"
                        + "\n"
                        + "<otherValue>D</otherValue>\n"
                        + "    </comment>\n"
                        + "</comments>";
        // When
        String payload = XxeScanRule.createLfrPayload(requestBody);
        // Then
        String expectedPayload =
                XxeScanRule.ATTACK_HEADER
                        + "\n"
                        + "\n"
                        + "<comments>\n"
                        + "    <comment>\n"
                        + "    <text>&zapxxe;</text>\n"
                        + "    </comment>\n"
                        + "\n"
                        + "    <comment>\n"
                        + "    <text>&zapxxe;</text>\n"
                        + "    </comment>\n"
                        + "    <comment>\n"
                        + "\n"
                        + "<otherValue>&zapxxe;</otherValue>\n"
                        + "<otherValue>&zapxxe;</otherValue>\n"
                        + "<otherValue>&zapxxe;</otherValue>\n"
                        + "\n"
                        + "<otherValue>&zapxxe;</otherValue>\n"
                        + "    </comment>\n"
                        + "</comments>";
        assertThat(payload, is(expectedPayload));
    }
}
