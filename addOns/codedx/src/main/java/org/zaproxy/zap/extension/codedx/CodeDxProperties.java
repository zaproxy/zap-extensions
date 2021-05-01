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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Paths;
import java.util.Properties;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;

public class CodeDxProperties {	
	private static class Holder {
		static final CodeDxProperties INSTANCE = new CodeDxProperties();
	}
	
	public static CodeDxProperties getInstance(){
		return Holder.INSTANCE;
	}
	
	private CodeDxProperties(){
		loadProperties();
	}
	
	private static final Logger LOGGER = LogManager.getLogger(CodeDxProperties.class);
	
	private static final String PROP_FILE = "codedx.properties";
	private static final String KEY_SERVER = "serverUrl";
	private static final String KEY_API = "apiKey";
	private static final String KEY_SELECTED = "selectedId";
	private static final String KEY_TIMEOUT = "timeout";

	private Properties prop;
	
	public static final String DEFAULT_TIMEOUT_STRING = "120";
	public static final int DEFAULT_TIMEOUT_INT = 120000;
	
	public String getServerUrl(){	
		String text = getProperty(KEY_SERVER);
		if(text.endsWith("/"))
			return text.substring(0, text.length()-1);
		return text;
	}
	
	public String getApiKey(){
		return getProperty(KEY_API);
	}
	
	public String getSelectedId(){
		return getProperty(KEY_SELECTED);
	}
	
	public String getTimeout() {
		String timeout = getProperty(KEY_TIMEOUT);
		if (timeout == null || timeout.isEmpty()) {
			timeout = DEFAULT_TIMEOUT_STRING;
		}
		return timeout;
	}
	
	private String getProperty(String key){
		String value = prop.getProperty(key); 
		return value == null ? "" : value;
	}
	
	public void setProperties(String server, String api, String selectedId, String timeout){
		prop.setProperty(KEY_SERVER, server);
		prop.setProperty(KEY_API, api);
		prop.setProperty(KEY_SELECTED, selectedId);
		prop.setProperty(KEY_TIMEOUT, timeout);
		saveProperties();
	}
	
	private void loadProperties(){
		if(prop == null)
			prop = new Properties();
		
		File f = Paths.get(Constant.getZapHome(), PROP_FILE).toFile();
		if(!f.exists()){
			try {
				f.createNewFile();
			} catch (IOException e) {
				LOGGER.error("Error creating codedx.properties file: ", e);
			}
		}
		
		if(f.exists()){
			try (FileInputStream inp = new FileInputStream(f)) {
				prop.load(inp);
			} catch (IOException e) {
				LOGGER.error("Error loading codedx.properties file: ", e);
			}
		}
	}
	
	private void saveProperties(){		
		File f = Paths.get(Constant.getZapHome(), PROP_FILE).toFile();
		try(FileOutputStream out = new FileOutputStream(f)){
			prop.store(out, null);
		} catch (IOException e) {
			LOGGER.error("Error saving codedx.properties file: ", e);
		}
	}
}