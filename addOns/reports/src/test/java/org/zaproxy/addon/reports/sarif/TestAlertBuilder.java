/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.addon.reports.sarif;

import org.apache.commons.httpclient.URI;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;

/**
 * A builder to simplify alert creation inside tests and provide a fluent API. The defaults will
 * result in a TEST alert, medium risk, medium confidence and some (but not valid) test content
 */
public class TestAlertBuilder {

    private int pluginId = 1;

    private String name = "TEST";
    private String description = "Test description";

    private int cweId = 123;
    private int wascId = 456;

    private int risk = Alert.RISK_MEDIUM;
    private int confidence = Alert.CONFIDENCE_MEDIUM;

    private String param = "Test Param";
    private String attack = "Test \"Attack\\\"";
    private String otherInfo;
    private String solution = "Test Solution";
    private String requestBody;
    private String responseBody = "Test Response Body";
    private String reference;
    private String evidence = "Test <p>Evidence</p>";
    private String uriString;
    private String requestHeader;
    private String responseHeader;

    private TestAlertBuilder() {}

    /**
     * Creates a new alert builder
     *
     * @return builder
     */
    public static TestAlertBuilder newAlertBuilder() {
        return new TestAlertBuilder();
    }

    public TestAlertBuilder setName(String name) {
        this.name = name;
        return this;
    }

    public TestAlertBuilder setDescription(String description) {
        this.description = description;
        return this;
    }

    public TestAlertBuilder setRisk(int risk) {
        this.risk = risk;
        return this;
    }

    public TestAlertBuilder setConfidence(int confidence) {
        this.confidence = confidence;
        return this;
    }

    public TestAlertBuilder setParam(String param) {
        this.param = param;
        return this;
    }

    public TestAlertBuilder setAttack(String attack) {
        this.attack = attack;
        return this;
    }

    public TestAlertBuilder setOtherInfo(String otherInfo) {
        this.otherInfo = otherInfo;
        return this;
    }

    public TestAlertBuilder setSolution(String solution) {
        this.solution = solution;
        return this;
    }

    public TestAlertBuilder setRequestHeader(String requestHeader) {
        this.requestHeader = requestHeader;
        return this;
    }

    public TestAlertBuilder setRequestBody(String requestBody) {
        this.requestBody = requestBody;
        return this;
    }

    public TestAlertBuilder setResponseBody(String responseBody) {
        this.responseBody = responseBody;
        return this;
    }

    public TestAlertBuilder setResponseHeader(String responseHeader) {
        this.responseHeader = responseHeader;
        return this;
    }

    public TestAlertBuilder setReference(String reference) {
        this.reference = reference;
        return this;
    }

    public TestAlertBuilder setEvidence(String evidence) {
        this.evidence = evidence;
        return this;
    }

    public TestAlertBuilder setCweId(int cweId) {
        this.cweId = cweId;
        return this;
    }

    public TestAlertBuilder setWascId(int wascId) {
        this.wascId = wascId;
        return this;
    }

    public TestAlertBuilder setUriString(String uriString) {
        this.uriString = uriString;
        return this;
    }

    public TestAlertBuilder setPluginId(int pluginId) {
        this.pluginId = pluginId;
        return this;
    }

    /**
     * @return created alert
     */
    public Alert build() {
        Alert alert = new Alert(pluginId, risk, confidence, name);

        if (uriString == null) {
            // when not explicit defined, create a generic example
            uriString = "http://example.com/example_" + risk;
        }

        HttpMessage httpMessage;
        try {
            httpMessage = new HttpMessage(new URI(uriString, true));
        } catch (Exception e) {
            throw new IllegalStateException("Should not happen - testcase corrupt?", e);
        }
        httpMessage.setRequestBody(requestBody);
        if (requestHeader != null) {
            try {
                httpMessage.setRequestHeader(requestHeader);
            } catch (HttpMalformedHeaderException e) {
                throw new IllegalArgumentException(
                        "requestHeader header not valid:\n" + requestHeader + "\n", e);
            }
        }
        httpMessage.setResponseBody(responseBody);
        if (responseHeader != null) {
            try {
                httpMessage.setResponseHeader(responseHeader);
            } catch (HttpMalformedHeaderException e) {
                throw new IllegalArgumentException(
                        "responseHeader header not valid:\n" + responseHeader + "\n", e);
            }
        }

        alert.setDetail(
                description,
                uriString,
                param,
                attack,
                otherInfo,
                solution,
                reference,
                evidence,
                cweId,
                wascId,
                httpMessage);

        return alert;
    }
}
