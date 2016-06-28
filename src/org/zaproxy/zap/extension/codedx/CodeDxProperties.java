/*
 * Copyright (C) 2016 Code Dx, Inc. - http://www.codedx.com
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

package org.zaproxy.zap.extension.codedx;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Paths;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;

public class CodeDxProperties {
	private static final Logger logger = Logger.getLogger(CodeDxProperties.class);
	
	private static String PROP_FILE = "codedx.properties";
	private static String KEY_SERVER = "serverUrl";
	private static String KEY_API = "apiKey";
	private static Properties prop;
	
	public static String getServerUrl(){	
		String text = getProperty(KEY_SERVER);
		if(text.endsWith("/"))
			return text.substring(0, text.length()-1);
		return text;
	}
	
	public static String getApiKey(){
		return getProperty(KEY_API);
	}
	
	private static String getProperty(String key){
		if(prop == null)
			loadProperties();
		return prop.getProperty(key);
	}
	
	public static void setProperties(String server, String api){
		if(prop == null)
			loadProperties();
		prop.setProperty(KEY_SERVER, server);
		prop.setProperty(KEY_API, api);
		saveProperties();
	}
	
	private static void loadProperties(){
		if(prop == null)
			prop = new Properties();
		
		File f = Paths.get(Constant.getZapHome(), PROP_FILE).toFile();
		if(!f.exists()){
			try {
				f.createNewFile();
			} catch (IOException e) {
				logger.error("Error creating codedx.properties file: ", e);
			}
		}
		
		if(f.exists()){
			try (FileInputStream inp = new FileInputStream(f)) {
				prop.load(inp);
			} catch (IOException e) {
				logger.error("Error loading codedx.properties file: ", e);
			}
		}
	}
	
	private static void saveProperties(){
		if(prop == null)
			loadProperties();
		
		File f = Paths.get(Constant.getZapHome(), PROP_FILE).toFile();
		try(FileOutputStream out = new FileOutputStream(f)){
			prop.store(out, null);
		} catch (IOException e) {
			logger.error("Error saving codedx.properties file: ", e);
		}
	}	
}
