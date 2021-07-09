/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.zaproxy.zap.extension.codedx;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.XMLEvent;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.mime.HttpMultipartMode;
import org.apache.http.entity.mime.MultipartEntityBuilder;
import org.apache.http.entity.mime.content.FileBody;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.util.EntityUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.codedx.ReportLastScan.ReportType;

public class UploadActionListener implements ActionListener{

	private static final Logger LOGGER = LogManager.getLogger(UploadActionListener.class);
	
	private static final XMLInputFactory xmlInputFactory = XMLInputFactory.newInstance();

	static {
		xmlInputFactory.setProperty(XMLInputFactory.IS_REPLACING_ENTITY_REFERENCES, false);
		xmlInputFactory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
	}

	private CodeDxExtension extension;
	private UploadPropertiesDialog prop;
	
	public UploadActionListener(CodeDxExtension extension) {
		this.extension = extension;
		this.prop = new UploadPropertiesDialog(extension);
	}
	
	@Override
	public void actionPerformed(ActionEvent e) {
		prop.openProperties(this);
	}
	
	public void generateAndUploadReport(){
		String error = null;
		try {
			final File reportFile = generateReportFile(extension);
			if(!reportIsEmpty(reportFile)) {
				Thread uploadThread = new Thread(){
					@Override
					public void run(){
						String err;
						try{
							err = uploadFile(
								extension.getHttpClient(),
								reportFile,
								CodeDxProperties.getInstance().getServerUrl(),
								CodeDxProperties.getInstance().getApiKey(),
								prop.getProject().getValue()
							);
						} catch (IOException ex1){
							err = Constant.messages.getString("codedx.error.unexpected");
							LOGGER.error("Unexpected error while uploading report: ", ex1);
						}
						if(err != null)
							View.getSingleton().showMessageDialog(err);
						else
							View.getSingleton().showMessageDialog(Constant.messages.getString("codedx.message.success"));
						reportFile.delete();
					}
				};
				uploadThread.start();
			} else {
				error = Constant.messages.getString("codedx.error.empty");
			}
		} catch (Exception ex2) {
			error = Constant.messages.getString("codedx.error.failed");
			LOGGER.error("Unexpected error while generating report: ", ex2);
		}
		if(error != null)
			View.getSingleton().showWarningDialog(error);
	}

	public static String uploadFile(
			CloseableHttpClient client,
			File reportFile,
			String serverUrl,
			String apiKey,
			String project
	) throws IOException {
		String err = null;
		HttpResponse response = sendData(
			client,
			reportFile,
			serverUrl,
			apiKey,
			project
		);
		StatusLine responseLine = null;
		int responseCode = -1;
		if(response != null){
			responseLine = response.getStatusLine();
			responseCode = responseLine.getStatusCode();
		}
		if(responseCode == 400) {
			err = Constant.messages.getString("codedx.error.unexpected") + "\n"
					+ Constant.messages.getString("codedx.error.http.400");
		} else if(responseCode == 403){
			err = Constant.messages.getString("codedx.error.unsent") + " "
					+ Constant.messages.getString("codedx.error.http.403");
		} else if(responseCode == 404){
			err = Constant.messages.getString("codedx.error.unsent") + " "
					+ Constant.messages.getString("codedx.error.http.404");
		} else if(responseCode == 415) {
			err = Constant.messages.getString("codedx.error.unexpected") + "\n"
					+ Constant.messages.getString("codedx.error.http.415");
		} else if(responseCode != 200 && responseCode != 202) {
			err = Constant.messages.getString("codedx.error.unexpected");
			if(response != null)
				err += Constant.messages.getString("codedx.error.http.other") + " " + responseLine;
		}
		return err;
	}
	
	private static HttpResponse sendData(
		CloseableHttpClient client,
		File reportFile,
		String serverUrl,
		String apiKey,
		String project
	) throws IOException{
		if(client == null)
			return null;
		try {
			HttpPost post = new HttpPost(serverUrl + "/api/projects/" + project + "/analysis");
			post.setHeader("API-Key", apiKey);
			
			MultipartEntityBuilder builder = MultipartEntityBuilder.create();
			builder.setMode(HttpMultipartMode.BROWSER_COMPATIBLE);
			builder.addPart("file", new FileBody(reportFile));
			
			HttpEntity entity = builder.build();
			post.setEntity(entity);

			HttpResponse response = client.execute(post);
			HttpEntity resEntity = response.getEntity();
			
			if (resEntity != null) {
				EntityUtils.consume(resEntity);
			}
			
			return response;
		} finally {
			client.close();
		}
	}
	
	public static void generateReportString(CodeDxExtension extension, StringBuilder report) throws Exception {
		ReportLastScanHttp saver = new ReportLastScanHttp();
		saver.generate(report);
	}

	public static File generateReportFile(CodeDxExtension extension) throws Exception {
		File reportFile = File.createTempFile("codedx-zap-report", ".xml");
		reportFile.deleteOnExit();

		ReportLastScanHttp saver = new ReportLastScanHttp();
		saver.generate(reportFile.getCanonicalPath(), ReportType.XML);

		return reportFile;
	}

	public static Boolean reportIsEmpty(File reportFile) throws IOException, XMLStreamException {
		BufferedReader br = Files.newBufferedReader(reportFile.toPath());
		try {
			XMLEventReader reader = xmlInputFactory.createXMLEventReader(br);

			while(reader.hasNext()) {
				XMLEvent event = reader.nextEvent();
				if(event.isStartElement() && !event.asStartElement().getName().getLocalPart().equals("OWASPZAPReport")) {
					return false;
				}
			}
		} finally {
			br.close();
		}
		return true;
	}
}
