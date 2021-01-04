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
package org.zaproxy.zap.extension.imagelocationscanner;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.nio.file.Files;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.testutils.PassiveScannerTestUtils;

public class ImageLocationScanRuleUnitTest extends PassiveScannerTestUtils<ImageLocationScanRule> {
    private static final int PLUGIN_ID = ImageLocationScanRule.PLUGIN_ID;
    private static final String URI = "https://www.example.com/";

    @Override
    protected void setUpMessages() {
        mockMessages(new ExtensionImageLocationScanner());
    }

    @Override
    protected ImageLocationScanRule createScanner() {
        return new ImageLocationScanRule();
    }

    @Test
    public void passesIfExifLocationDetected() throws HttpMalformedHeaderException, IOException {
        HttpMessage msg;
        String fname;

        // Given - image file containing GPS Exif data
        fname = "exif_gps_01.jpg";

        // When
        msg = createHttpMessageFromFilename(fname);
        scanHttpResponseReceive(msg);

        // Then
        assertEquals(alertsRaised.size(), 1);
        validateAlert(alertsRaised.get(0));
        assertThat(alertsRaised.get(0).getEvidence(), containsString("Exif_GPS"));
    }

    @Test
    public void passesIfNoIssuesDetected() throws HttpMalformedHeaderException, IOException {
        HttpMessage msg;
        String fname;

        // Given - image file with no Exif data
        fname = "no_alerts_01.jpg";

        // When
        msg = createHttpMessageFromFilename(fname);
        scanHttpResponseReceive(msg);

        // Then
        assertEquals(alertsRaised.size(), 0);

        // Given
        // a non-image file, like a text file
        fname = "README.md";

        // When
        msg = createHttpMessageFromFilename(fname);
        scanHttpResponseReceive(msg);

        // Then
        assertEquals(alertsRaised.size(), 0);
    }

    @Test
    public void passesIfPrivacyExposureDetected() throws HttpMalformedHeaderException, IOException {
        HttpMessage msg;
        String fname;

        // Given - image with privacy-exposure (embedded camera ownership)
        fname = "privacy_exposure_01.jpg";

        // When
        msg = createHttpMessageFromFilename(fname);
        scanHttpResponseReceive(msg);

        // Then
        assertEquals(alertsRaised.size(), 1);
        validateAlert(alertsRaised.get(0));
        assertThat(alertsRaised.get(0).getEvidence(), containsString("Owner Name"));
    }

    @Test
    public void testOfScanHttpRequestSend() throws HttpMalformedHeaderException {
        // the method should do nothing (test just for code coverage)
        rule.scanHttpRequestSend(null, -1);
        assertThat(alertsRaised.size(), equalTo(0));
    }

    private static void validateAlert(Alert alert) {
        assertThat(alert.getPluginId(), equalTo(PLUGIN_ID));
        assertThat(alert.getRisk(), equalTo(Alert.RISK_INFO));
        assertThat(alert.getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
        assertThat(alert.getUri(), equalTo(URI));
    }

    private HttpMessage createHttpMessageFromFilename(String filename)
            throws HttpMalformedHeaderException, IOException {
        HttpMessage msg = new HttpMessage();
        String requestUri = URI;

        msg.setRequestHeader("GET " + requestUri + " HTTP/1.1");

        msg.setResponseHeader("HTTP/1.1 200 OK\r\n" + "Content-Type: image/jpg\r\n");
        msg.setResponseBody(Files.readAllBytes(getResourcePath(filename)));

        return msg;
    }
}

// vim: autoindent noexpandtab tabstop=4 shiftwidth=4
