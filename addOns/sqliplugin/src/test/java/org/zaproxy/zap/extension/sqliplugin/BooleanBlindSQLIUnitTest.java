/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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
package org.zaproxy.zap.extension.sqliplugin;

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.junit.jupiter.api.Assertions.assertEquals;

import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.zaproxy.zap.testutils.ActiveScannerTestUtils;
import org.zaproxy.zap.testutils.NanoServerHandler;

public class BooleanBlindSQLIUnitTest extends ActiveScannerTestUtils<SQLInjectionScanRule> {

    @Override
    protected int getRecommendMaxNumberMessagesPerParam(AttackStrength strength) {
        int recommendMax = super.getRecommendMaxNumberMessagesPerParam(strength);
        switch (strength) {
            case LOW:
            case MEDIUM:
                return recommendMax + 222;
            case HIGH:
                return recommendMax + 915;
            case INSANE:
                return recommendMax + 3627;
            default:
                return recommendMax;
        }
    }

    @Override
    protected SQLInjectionScanRule createScanner() {
        return new SQLInjectionScanRule();
    }

    @Test
    void shouldRaiseAlertIfTrueAndFalseInBooleanBasedSQLiResponseAreNotSame()
            throws HttpMalformedHeaderException {
        // Given
        String path = "/shouldRaiseAlertIfTrueAndFalseInBooleanBasedSQLiResponseAreNotSame/";
        this.nano.addHandler(
                new NanoServerHandler(path) {
                    boolean isInitialFalseMessageDone = false;
                    boolean isTrueMessageDone = false;
                    boolean isSecondFalseMessageDone = false;

                    @Override
                    protected Response serve(IHTTPSession session) {
                        if (isInitialFalseMessageDone
                                && isSecondFalseMessageDone
                                && isTrueMessageDone) {
                            isInitialFalseMessageDone = false;
                            isSecondFalseMessageDone = false;
                            isTrueMessageDone = false;
                        }
                        if (!isInitialFalseMessageDone) {
                            isInitialFalseMessageDone = true;
                            return newFixedLengthResponse(
                                    Response.Status.INTERNAL_ERROR,
                                    "text/html",
                                    generateFalseMessageForBooleanBasedSQLi());
                        } else if (!isTrueMessageDone) {
                            isTrueMessageDone = true;
                            return newFixedLengthResponse(
                                    Response.Status.OK,
                                    "text/html",
                                    generateTrueMessageForBooleanBasedSQLi());
                        } else if (!isSecondFalseMessageDone) {
                            isSecondFalseMessageDone = true;
                            return newFixedLengthResponse(
                                    Response.Status.INTERNAL_ERROR,
                                    "text/html",
                                    generateFalseMessageForBooleanBasedSQLi());
                        }
                        return newFixedLengthResponse("");
                    }
                });
        // When
        rule.init(this.getHttpMessage(path + "?id="), this.parent);
        rule.scan();
        // Then
        assertEquals(alertsRaised.size(), 1);
    }

    @Test
    void shouldNotRaiseAlertIfTrueAndFalseResponsesInBooleanBasedSQLiAreSame()
            throws HttpMalformedHeaderException {
        String path = "/shouldNotRaiseAlertIfTrueAndFalseResponsesInBooleanBasedSQLiAreSame/";
        this.nano.addHandler(
                new NanoServerHandler(path) {
                    boolean isInitialFalseMessageDone = false;
                    boolean isTrueMessageDone = false;
                    boolean isSecondFalseMessageDone = false;

                    @Override
                    protected Response serve(IHTTPSession session) {
                        if (isInitialFalseMessageDone
                                && isSecondFalseMessageDone
                                && isTrueMessageDone) {
                            isInitialFalseMessageDone = false;
                            isSecondFalseMessageDone = false;
                            isTrueMessageDone = false;
                        }
                        if (!isInitialFalseMessageDone) {
                            isInitialFalseMessageDone = true;
                            return newFixedLengthResponse(
                                    Response.Status.BAD_REQUEST,
                                    "text/html",
                                    generateNeutralErrorMessageForBooleanBasedSQLi());
                        } else if (!isTrueMessageDone) {
                            isTrueMessageDone = true;
                            return newFixedLengthResponse(
                                    Response.Status.BAD_REQUEST,
                                    "text/html",
                                    generateNeutralErrorMessageForBooleanBasedSQLi());
                        } else if (!isSecondFalseMessageDone) {
                            isSecondFalseMessageDone = true;
                            return newFixedLengthResponse(
                                    Response.Status.BAD_REQUEST,
                                    "text/html",
                                    generateNeutralErrorMessageForBooleanBasedSQLi());
                        }
                        return newFixedLengthResponse("");
                    }
                });
        // When
        rule.init(this.getHttpMessage(path + "?id="), this.parent);
        rule.scan();
        // Then
        assertEquals(alertsRaised.size(), 0);
    }

    @Override
    protected void setUpMessages() {
        mockMessages(new ExtensionLoader());
    }

    private String generateTrueMessageForBooleanBasedSQLi() {
        return "<html><body><h1>Found a response. The SQL query succeeded and returned a response</h1></body>/<html>";
    }

    private String generateFalseMessageForBooleanBasedSQLi() {
        return "<html><body><h1>This request causes an error which could be an SQL injection error</h1></body></html>";
    }

    private String generateNeutralErrorMessageForBooleanBasedSQLi() {
        return "<html><body><h1>Invalid request. Please consult the documentation</h1></body></html>";
    }
}

class ExtensionLoader extends ExtensionAdaptor {}
