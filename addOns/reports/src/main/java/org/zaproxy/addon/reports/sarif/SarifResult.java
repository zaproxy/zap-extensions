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

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpBody;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpHeaderField;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpResponseHeader;

public class SarifResult implements Comparable<SarifResult> {

    private SarifLevel level = SarifLevel.NONE;
    private SarifMessage message;
    private List<SarifResultLocation> locations = new ArrayList<>();
    private SarifWebRequest webRequest = new SarifWebRequest();
    private SarifWebResponse webResponse = new SarifWebResponse();
    private int pluginId;
    private String ruleId;

    public SarifWebRequest getWebRequest() {
        return webRequest;
    }

    public SarifWebResponse getWebResponse() {
        return webResponse;
    }

    public static SarifResultBuilder builder() {
        return new SarifResultBuilder();
    }

    public static class SarifResultBuilder {

        private SarifResultBuilder() {
            // force static method call
        }

        private SarifBinaryContentDetector binaryContentDetector;
        private SarifBase64Encoder base64Encoder;
        private Alert alert;

        public SarifResultBuilder setAlert(Alert alert) {
            this.alert = alert;
            return this;
        }

        public SarifResultBuilder setBinaryContentDetector(
                SarifBinaryContentDetector binaryContentDetector) {
            this.binaryContentDetector = binaryContentDetector;
            return this;
        }

        public SarifResultBuilder setBase64Encoder(SarifBase64Encoder base64Encoder) {
            this.base64Encoder = base64Encoder;
            return this;
        }

        public SarifResult build() {
            if (base64Encoder == null) {
                base64Encoder = SarifBase64Encoder.DEFAULT;
            }

            if (binaryContentDetector == null) {
                binaryContentDetector = SarifBinaryContentDetector.DEFAULT;
            }

            SarifResult result = new SarifResult();
            /* base parts */
            result.level = SarifLevel.fromAlertRisk(alert.getRisk());
            result.pluginId = alert.getPluginId();

            String messageText =
                    alert.getOtherInfo(); // if possible use other info which has more details
            if (messageText == null || messageText.trim().isEmpty()) {
                // no other info available - this depends on the alert rule implementation...
                messageText = alert.getDescription(); // fallback to description
            }
            result.message = SarifMessage.builder().setContentAsHTML(messageText).build();
            result.ruleId = "" + alert.getPluginId();

            /* location */
            SarifResultLocation resultLocation = new SarifResultLocation();

            String attack = alert.getAttack();
            resultLocation.physicalLocation.artifactLocation.uri = alert.getUri();
            resultLocation.properties.attack = attack;
            resultLocation.properties.evidence = alert.getEvidence();

            result.locations.add(resultLocation);

            HttpMessage httpMessage = alert.getMessage();

            /* ----------- */
            /* Web request */
            /* ----------- */
            SarifWebRequest webRequest = result.webRequest;
            HttpRequestHeader requestHeader = httpMessage.getRequestHeader();
            handleBody(webRequest.body, requestHeader, httpMessage.getRequestBody());

            List<HttpHeaderField> requestHeaders = requestHeader.getHeaders();
            for (HttpHeaderField headerField : requestHeaders) {
                webRequest.headers.put(headerField.getName(), headerField.getValue());
            }
            SarifProtocolData requestProtocolData =
                    SarifProtocolData.parseProtocolAndVersion(requestHeader.getVersion());
            webRequest.protocol = requestProtocolData.getProtocol();
            webRequest.version = requestProtocolData.getVersion();
            webRequest.target = safeToString(requestHeader.getURI());
            webRequest.method = requestHeader.getMethod();

            /* ------------ */
            /* Web response */
            /* ------------ */
            SarifWebResponse webResponse = result.webResponse;
            HttpResponseHeader responseHeader = httpMessage.getResponseHeader();
            handleBody(webResponse.body, responseHeader, httpMessage.getResponseBody());

            responseHeader.getNormalisedContentTypeValue();

            List<HttpHeaderField> responseHeaders = responseHeader.getHeaders();
            for (HttpHeaderField headerField : responseHeaders) {
                webResponse.headers.put(headerField.getName(), headerField.getValue());
            }
            webResponse.statusCode = responseHeader.getStatusCode();
            webResponse.reasonPhrase = responseHeader.getReasonPhrase();

            SarifProtocolData responseProtocolData =
                    SarifProtocolData.parseProtocolAndVersion(responseHeader.getVersion());
            webResponse.protocol = responseProtocolData.getProtocol();
            webResponse.version = responseProtocolData.getVersion();

            webResponse.noResponseReceived = responseHeader.isConnectionClose();

            /* build physical location region by repsonse body + attack */
            resultLocation.physicalLocation.region.snippet =
                    SarifMessage.builder().setContentAsPlainText(attack).build();

            SarifBodyStartLineFinder startLineFinder = SarifBodyStartLineFinder.DEFAULT;
            long startLine = startLineFinder.findStartLine(webResponse.body, attack);
            if (startLine == 0) {
                // fallback to evidence when not found by attack
                startLineFinder.findStartLine(webResponse.body, alert.getEvidence());
            }
            resultLocation.physicalLocation.region.startLine = startLine;

            return result;
        }

        private void handleBody(SarifBody sarifBody, HttpHeader header, HttpBody body) {
            if (binaryContentDetector.isBinaryContent(header)) {
                sarifBody.binary = encodeBodyToBase64(body);
            } else {
                sarifBody.text = safeToString(body);
            }
        }

        private String encodeBodyToBase64(HttpBody body) {
            if (body == null) {
                return null;
            }
            return base64Encoder.encodeBytesToBase64(body.getBytes());
        }

        private String safeToString(Object object) {
            if (object == null) {
                return null;
            }
            return object.toString();
        }
    }

    public String getRuleId() {
        return ruleId;
    }

    public SarifMessage getMessage() {
        return message;
    }

    public SarifLevel getLevel() {
        return level;
    }

    public List<SarifResultLocation> getLocations() {
        return locations;
    }

    public static class SarifResultLocation {
        SarifPhysicalLocation physicalLocation = new SarifPhysicalLocation();
        SarifResultLocationProperties properties = new SarifResultLocationProperties();

        public SarifPhysicalLocation getPhysicalLocation() {
            return physicalLocation;
        }

        public SarifResultLocationProperties getProperties() {
            return properties;
        }
    }

    public static class SarifResultLocationProperties {
        private String attack;
        private String evidence;

        public String getAttack() {
            return attack;
        }

        public String getEvidence() {
            return evidence;
        }
    }

    public static class SarifPhysicalLocation {
        SarifArtifactLocation artifactLocation = new SarifArtifactLocation();
        SarifRegion region = new SarifRegion();

        public SarifArtifactLocation getArtifactLocation() {
            return artifactLocation;
        }

        public SarifRegion getRegion() {
            return region;
        }
    }

    public static class SarifRegion {

        long startLine;
        SarifMessage snippet;

        public long getStartLine() {
            return startLine;
        }

        public SarifMessage getSnippet() {
            return snippet;
        }
    }

    public static class SarifArtifactLocation {
        private String uri;

        public String getUri() {
            return uri;
        }
    }

    public static class SarifBody {

        private String text;
        private String binary;

        public String getText() {
            return text;
        }

        public boolean isContainingText() {
            return !isContainingBinary() && text != null && !text.isEmpty();
        }

        public boolean isContainingBinary() {
            return binary != null && !binary.isEmpty();
        }

        public String getBinary() {
            return binary;
        }
    }

    public class SarifWebRequest {
        private String protocol;
        private String version;
        private String target;
        private String method;
        private Map<String, String> headers = new TreeMap<>();
        private SarifBody body = new SarifBody();

        public String getProtocol() {
            return protocol;
        }

        public String getVersion() {
            return version;
        }

        public String getTarget() {
            return target;
        }

        public String getMethod() {
            return method;
        }

        public Map<String, String> getHeaders() {
            return headers;
        }

        public SarifBody getBody() {
            return body;
        }
    }

    public class SarifWebResponse {
        private String protocol;
        private String version;
        private Map<String, String> headers = new TreeMap<>();
        private SarifBody body = new SarifBody();

        private int statusCode;
        private String reasonPhrase;
        private boolean noResponseReceived;

        public String getProtocol() {
            return protocol;
        }

        public String getReasonPhrase() {
            return reasonPhrase;
        }

        public String getVersion() {
            return version;
        }

        public Map<String, String> getHeaders() {
            return headers;
        }

        public SarifBody getBody() {
            return body;
        }

        public int getStatusCode() {
            return statusCode;
        }

        public boolean isNoResponseReceived() {
            return noResponseReceived;
        }
    }

    @Override
    public int compareTo(SarifResult o) {
        /* level/risk is descending - High, Medium, Low, None... */
        int levelCompared = o.level.getAlertRisk() - level.getAlertRisk();
        if (levelCompared != 0) {
            return levelCompared;
        }
        /* plugin id is ascending sorted */
        return pluginId - o.pluginId;
    }
}
