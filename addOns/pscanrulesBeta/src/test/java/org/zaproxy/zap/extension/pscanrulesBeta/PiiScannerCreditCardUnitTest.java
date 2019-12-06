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
package org.zaproxy.zap.extension.pscanrulesBeta;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

import java.util.Arrays;
import java.util.Collection;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.parosproxy.paros.network.HttpMessage;

/** @author Michael Kruglos (@michaelkruglos) */
@RunWith(Parameterized.class)
public class PiiScannerCreditCardUnitTest extends PassiveScannerTest<PiiScanner> {

    @Parameterized.Parameters
    public static Collection<Object[]> data() {
        // the numbers below are random
        return Arrays.asList(
                new Object[][] {
                    {"AmericanExpress", "370695954010459"},
                    {"AmericanExpress with spaces", "370 6959 5401 0459"},
                    {"DinersClub", "30538761461899"},
                    {"Discover", "6011377412263580"},
                    {"Jcb", "3589738566381370"},
                    {"Maestro", "6762355337694692"},
                    {"Mastercard", "5264810966944441"},
                    {"Mastercard with spaces", "5264 8109 66944441"},
                    {"Visa", "4716186978544330"},
                    {"Visa with spaces", "4716 1869 7854 4330"}
                });
    }

    @Parameterized.Parameter() public String cardType;

    @Parameterized.Parameter(1)
    public String cardNumber;

    @Override
    protected PiiScanner createScanner() {
        return new PiiScanner();
    }

    @Test
    public void shouldRaiseAlertWhenCreditCardIsDetected() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
        msg.setResponseHeader("HTTP/1.1 200 OK\r\n" + "Server: Apache-Coyote/1.1\r\n");
        msg.setResponseBody("{\"cc\": \"" + cardNumber + "\"}");

        // When
        rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

        // Then
        assertThat(alertsRaised.size(), is(1));
        assertThat(alertsRaised.get(0).getName(), equalTo("PII Scanner"));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo(cardNumber.replaceAll("\\s+", "")));
    }
}
