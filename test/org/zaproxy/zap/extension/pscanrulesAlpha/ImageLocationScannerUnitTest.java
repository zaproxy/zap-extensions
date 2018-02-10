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

package org.zaproxy.zap.extension.pscanrulesAlpha;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

import org.junit.Test;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

public class ImageLocationScannerUnitTest extends PassiveScannerTest {
	private static final int PLUGIN_ID = 10103;
	private static final String URI = "https://www.example.com/";
	private static final String images_dir = "/Users/evilkitten/proj/ZAP/zap-extensions/test/resources/org/zaproxy/zap/extension/imagelocationscanner";

	@Override
	protected PluginPassiveScanner createScanner() {
		return new ImageLocationScanner();
	}

	@Test
	public void passesIfExifLocationDetected() throws HttpMalformedHeaderException, IOException {
		// future: add more files, put in a loop.
		String fname= "exif_gps_01.jpg";
		HttpMessage msg = createHttpMessageFromFilename(fname);
		rule.scanHttpResponseReceive(msg, -1, createSource(msg));
		/*
		System.out.println("Body: " + String.format("%x", msg.getResponseBody().getBytes()[1]));
		System.out.println("plug: " + rule.getName());
		System.out.println("Data: " + alertsRaised.get(0).getEvidence());
		*/
		assertEquals(alertsRaised.size(), 1);
		validateAlert(URI,alertsRaised.get(0));
		assertThat(alertsRaised.get(0).getEvidence(), containsString("Exif_GPS"));
	}

	@Test
	public void passesIfNoIssuesDetected() throws HttpMalformedHeaderException, IOException {
		// future: add more files, put in a loop.
		String fname= "no_alerts_01.jpg";
		HttpMessage msg = createHttpMessageFromFilename(fname);
		rule.scanHttpResponseReceive(msg, -1, createSource(msg));

		assertEquals(alertsRaised.size(), 0);
		
		fname= "README.md";
		msg = createHttpMessageFromFilename(fname);
		rule.scanHttpResponseReceive(msg, -1, createSource(msg));

		assertEquals(alertsRaised.size(), 0);
	}

	@Test
	public void passesIfPrivacyExposureDetected() throws HttpMalformedHeaderException, IOException {
		// future: add more files, put in a loop.
		String fname= "privacy_exposure_01.jpg";
		HttpMessage msg = createHttpMessageFromFilename(fname);
		rule.scanHttpResponseReceive(msg, -1, createSource(msg));

		assertEquals(alertsRaised.size(), 1);
		System.out.println("Data: " + alertsRaised.get(0).getEvidence());
		assertThat(alertsRaised.get(0).getEvidence(), containsString("Serial Number"));
	}

	
	@Test
	public void testOfScanHttpRequestSend() throws HttpMalformedHeaderException {
		// the method should do nothing (test just for code coverage)
		rule.scanHttpRequestSend(null, -1);
		assertThat(alertsRaised.size(), equalTo(0));
	}


	private static void validateAlert(Alert alert) {
		validateAlert(URI, alert);
	}

	private static void validateAlert(String requestUri, Alert alert) {
		assertThat(alert.getPluginId(), equalTo(PLUGIN_ID));
		assertThat(alert.getRisk(), equalTo(Alert.RISK_INFO));
		assertThat(alert.getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
		assertThat(alert.getUri(), equalTo(requestUri));
	}

	private HttpMessage createHttpMessage(String body) throws HttpMalformedHeaderException {
		return createHttpMessage(URI, body);
	}
	
	private HttpMessage createHttpMessageFromFilename(String filename) throws HttpMalformedHeaderException, IOException {
		
		String fullpath = images_dir + "/" + filename;
		// System.out.println("Reading file: " + fullpath);
		
		File file = new File(fullpath);
		FileInputStream fis = new FileInputStream(file);
		byte[] data = new byte[(int) file.length()];
		fis.read(data);
		fis.close();
		// System.out.println("Read Size: " + data.length);
		
		return createHttpMessage(URI, data);
	}

	// TODO : have one createHttpMessage call the other...
	
	private HttpMessage createHttpMessage(String requestUri, String body) throws HttpMalformedHeaderException {
		HttpMessage msg = new HttpMessage();
		requestUri = requestUri.startsWith("http") ? requestUri : "http://" + requestUri;
		msg.setRequestHeader("GET " + requestUri + " HTTP/1.1");
		msg.setResponseHeader("HTTP/1.1 200 OK\r\n");
		msg.setResponseBody(body);
		return msg;
	}

	private HttpMessage createHttpMessage(String requestUri, byte[] data) throws HttpMalformedHeaderException {
		HttpMessage msg = new HttpMessage();
		requestUri = requestUri.startsWith("http") ? requestUri : "http://" + requestUri;
		msg.setRequestHeader("GET " + requestUri + " HTTP/1.1");
		
		// Future testing might add checks for content type or file extensions, but for now, the 
		// important part is getting the image scanning correct.
		
		msg.setResponseHeader(	"HTTP/1.1 200 OK\r\n"
								+ "Content-Type: image/jpg\r\n"
							);
		msg.setResponseBody(data);

		return msg;
	}

}

// vim: autoindent noexpandtab tabstop=4 shiftwidth=4