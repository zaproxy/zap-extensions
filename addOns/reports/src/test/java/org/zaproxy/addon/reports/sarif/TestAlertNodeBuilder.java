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

import static java.util.Objects.requireNonNull;

import java.util.ArrayList;
import java.util.List;
import org.apache.commons.httpclient.URI;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.alert.AlertNode;

public class TestAlertNodeBuilder {

    private Alert firstAlert;
    private List<Alert> otherInstanceAlerts = new ArrayList<>();

    private TestAlertNodeBuilder() {}

    public static TestAlertNodeBuilder newAlertNodeBuilder(Alert firstAlert) {
        requireNonNull(firstAlert, "first alert may bot be null!");

        TestAlertNodeBuilder builder = new TestAlertNodeBuilder();
        builder.firstAlert = firstAlert;
        return builder;
    }

    public class TestNewInstanceBuilder {

        private String uriString = "undefined";
        private String requestBody = "";
        private String responseBody = "";
        private String requestHeader;
        private String responseHeader;
        private String otherInfo;

        public TestNewInstanceBuilder setOtherInfo(String otherInfo) {
            this.otherInfo = otherInfo;
            return this;
        }

        public TestNewInstanceBuilder setUri(String uri) {
            this.uriString = uri;
            return this;
        }

        public TestNewInstanceBuilder setRequestBody(String requestBody) {
            this.requestBody = requestBody;
            return this;
        }

        public TestNewInstanceBuilder setResponseBody(String responseBody) {
            this.responseBody = responseBody;
            return this;
        }

        public TestNewInstanceBuilder setRequestHeader(String requestHeader) {
            this.requestHeader = requestHeader;
            return this;
        }

        public TestNewInstanceBuilder setResponseHeader(String responseHeader) {
            this.responseHeader = responseHeader;
            return this;
        }

        /**
         * Builds new instance and adds to sub root node.
         *
         * @return alert node builder
         */
        public TestAlertNodeBuilder add() {
            Alert alert = build();
            otherInstanceAlerts.add(alert);
            return TestAlertNodeBuilder.this;
        }

        /**
         * Builds new instance
         *
         * @return alert
         */
        public Alert build() {
            Alert instanceAlert = firstAlert.newInstance();

            HttpMessage httpMessage;
            try {
                httpMessage = new HttpMessage(new URI(uriString, true));
            } catch (Exception e) {
                throw new IllegalStateException("Should not happen - testcase corrupt?", e);
            }
            httpMessage.setRequestBody(requestBody);
            httpMessage.setResponseBody(responseBody);

            if (requestHeader != null) {
                try {
                    httpMessage.setRequestHeader(requestHeader);
                } catch (HttpMalformedHeaderException e) {
                    throw new IllegalStateException("test case wrong implemented", e);
                }
            }

            if (responseHeader != null) {
                try {
                    httpMessage.setResponseHeader(responseHeader);
                } catch (HttpMalformedHeaderException e) {
                    throw new IllegalStateException("test case wrong implemented", e);
                }
            }

            if (otherInfo != null) {
                instanceAlert.setOtherInfo(otherInfo);
            }
            instanceAlert.setMessage(httpMessage);
            instanceAlert.setUri(uriString);
            return instanceAlert;
        }
    }

    /**
     * Creates a new instance builder, which creates new instances based on the first alert.
     *
     * @return builder to define new instance
     */
    public TestNewInstanceBuilder newInstance() {
        return new TestNewInstanceBuilder();
    }

    public AlertNode build() {
        AlertNode alertRootSubNode = new AlertNode(firstAlert.getRisk(), firstAlert.getName());
        alertRootSubNode.setUserObject(firstAlert);

        // build sub node as in real ZAP UI - there the URI is shown
        AlertNode firstChild = new AlertNode(firstAlert.getRisk(), firstAlert.getUri());
        firstChild.setUserObject(firstAlert);
        alertRootSubNode.add(firstChild);

        // build other instances sub nodes
        for (Alert otherInstanceAlert : otherInstanceAlerts) {
            AlertNode otherChild =
                    new AlertNode(otherInstanceAlert.getRisk(), otherInstanceAlert.getUri());
            otherChild.setUserObject(otherInstanceAlert);
            alertRootSubNode.add(otherChild);
        }

        return alertRootSubNode;
    }
}
