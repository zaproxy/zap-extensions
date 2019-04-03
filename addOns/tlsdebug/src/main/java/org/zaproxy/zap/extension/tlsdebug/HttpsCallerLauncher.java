/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP development team
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS"
 * BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language
 * governing permissions and limitations under the License.
 */
package org.zaproxy.zap.extension.tlsdebug;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;

public class HttpsCallerLauncher {

	private static String SEP = System.getProperty("path.separator");
	private static final Logger logger = Logger.getLogger(HttpsCallerLauncher.class);
	
	private ExtensionTlsDebug extension;

	public HttpsCallerLauncher(ExtensionTlsDebug extension) {
		this.extension = extension;
	}

	public void startProcess(URL url, String debugStatus) throws IOException {

		ProcessBuilder pb = new ProcessBuilder(getArgumentsList(url, debugStatus));
		Process p = pb.start();
		pb.redirectErrorStream(true);

		Thread tout = new Thread(new StreamController(p.getInputStream()));
		tout.start();
		try {
			tout.join();
		} catch (InterruptedException e) {
			logger.debug(e);
		}
	}

	private List<String> getArgumentsList(URL url, String debugStatus) throws IOException {
		List<String> argumentsList = new ArrayList<String>();
		argumentsList.add(System.getProperty("java.home") + "/bin/java");
		argumentsList.add("-classpath");
		argumentsList.add(getClasspath());
		argumentsList.add("-Djavax.net.debug=" + debugStatus);
		argumentsList.add(HttpsCallerProcess.class.getName());
		argumentsList.add(url.toString());
		return argumentsList;
	}

	private String getClasspath() throws IOException {
		StringBuilder classpath = new StringBuilder(System.getProperty("java.class.path"));
		// /lang for message bundles
		classpath.append(SEP).append(Constant.getZapInstall()).append("lang");
		// path to TLS Debug extension
		String pluginPath = extension.getAddOn().getFile().getCanonicalPath();
		classpath.append(SEP).append(pluginPath);
		return classpath.toString();
	}

	private class StreamController implements Runnable {

		private BufferedReader reader;

		public StreamController(InputStream in) {
			InputStreamReader inr = new InputStreamReader(in);
			reader = new BufferedReader(inr);
		}

		@Override
		public void run() {
			try {
				String line = null;
				while ((line = reader.readLine()) != null) {
					extension.notifyResponse(line + "\n");
				}
			} catch (IOException e) {
				logger.debug(e);
			}
		}
	}
}