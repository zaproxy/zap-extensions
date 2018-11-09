/*
* Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 * 
 * Copyright the ZAP Development Team
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
package org.zaproxy.zap.extension.api;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.ResourceBundle;

import org.zaproxy.zap.extension.api.ApiImplementor;
import org.zaproxy.zap.extension.api.JavaAPIGenerator;
import org.zaproxy.zap.extension.api.NodeJSAPIGenerator;
import org.zaproxy.zap.extension.api.PhpAPIGenerator;
import org.zaproxy.zap.extension.api.PythonAPIGenerator;
import org.zaproxy.zap.extension.reveal.RevealAPI;
import org.zaproxy.zap.extension.selenium.SeleniumAPI;
import org.zaproxy.zap.extension.selenium.SeleniumOptions;
import org.zaproxy.zap.extension.spiderAjax.AjaxSpiderAPI;
import org.zaproxy.zap.extension.spiderAjax.AjaxSpiderParam;
import org.zaproxy.zap.extension.websocket.WebSocketAPI;

public class ApiGenerator {

	private static final String JAVA_OUTPUT_DIR = "../zap-api-java/subprojects/zap-clientapi/src/main/java/org/zaproxy/clientapi/gen";

	private static final String PHP_OUTPUT_DIR = "../zaproxy/php/api/zapv2/src/Zap";

	private static final String PYTHON_OUTPUT_DIR = "../zap-api-python/src/zapv2/";

	private static final String NODE_OUTPUT_DIR = "../zap-api-nodejs/src/";

	public static List<ApiImplementor> getApiImplementors() {
		List<ApiImplementor> list = new ArrayList<ApiImplementor>();
		
		// If you implement an API for a _release_ add-on please add it here (in alphabetical order)
		// so that all of the client APIs are generated
		// Note that the following files will also need to be edited manually:
		//    __init__.py (in zap-api-python project)
		//    ClientApi.java (in zap-api-java project)
		// In zaproxy project:
		// 	nodejs/api/zapv2/index.js
		//	php/api/zapv2/src/Zap/Zapv2.php

		ApiImplementor api;

		api = new AjaxSpiderAPI(null);
		api.addApiOptions(new AjaxSpiderParam());
		list.add(api);

		list.add(new RevealAPI(null));
		list.add(new SeleniumAPI(new SeleniumOptions()));
		list.add(new WebSocketAPI(null));

		return list;
	}
	
	/**
	 * @param args
	 */
	public static void main(String[] args) {
		List<ApiGeneratorWrapper> generators = Arrays.asList(
				wrapper(JavaAPIGenerator.class, JAVA_OUTPUT_DIR),
				wrapper(NodeJSAPIGenerator.class, NODE_OUTPUT_DIR),
				wrapper(PhpAPIGenerator.class, PHP_OUTPUT_DIR),
				wrapper(PythonAPIGenerator.class, PYTHON_OUTPUT_DIR)
				// wrapper(WikiAPIGenerator.class, "../zaproxy-wiki")
		);
		getApiImplementors().forEach(api -> {
			ResourceBundle bundle = ResourceBundle.getBundle(
					api.getClass().getPackage().getName() + ".resources.Messages",
					Locale.ENGLISH,
					api.getClass().getClassLoader(),
					ResourceBundle.Control.getControl(ResourceBundle.Control.FORMAT_PROPERTIES));

			generators.forEach(generator -> generator.generate(api, bundle));
		});
	}

	private static ApiGeneratorWrapper wrapper(Class<? extends AbstractAPIGenerator> clazz, String outputDir) {
		return new ApiGeneratorWrapper(clazz, outputDir);
	}

	private static class ApiGeneratorWrapper {

		private final Class<? extends AbstractAPIGenerator> clazz;
		private final String outputDir;

		public ApiGeneratorWrapper(Class<? extends AbstractAPIGenerator> clazz, String outputDir) {
			this.clazz = clazz;
			this.outputDir = outputDir;
		}

		public void generate(ApiImplementor api, ResourceBundle bundle) {
			AbstractAPIGenerator generator;
			try {
				generator = createInstance(bundle);
			} catch (Exception e) {
				throw new RuntimeException(e);
			}

			try {
				generator.generateAPIFiles(Arrays.asList(api));
			} catch (IOException e) {
				throw new UncheckedIOException(e);
			}
		}

		private AbstractAPIGenerator createInstance(ResourceBundle bundle) throws Exception {
			try {
				return clazz.getDeclaredConstructor(String.class, boolean.class, ResourceBundle.class)
						.newInstance(outputDir, true, bundle);
			} catch (NoSuchMethodException e) {
				System.out.println("Defaulting to generator without ResourceBundle, no descriptions will be included.");
				return clazz.getDeclaredConstructor(String.class, boolean.class).newInstance(outputDir, true);
			}
		}
	}

}
