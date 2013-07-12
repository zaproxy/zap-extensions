/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2013 The ZAP development team
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

package org.zaproxy.zap.extension.scripts.javascript;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;

import javax.script.ScriptEngine;
import javax.swing.ImageIcon;

import org.apache.log4j.Logger;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.zaproxy.zap.extension.scripts.ScriptEngineWrapper;

public class JavascriptEngineWrapper extends ScriptEngineWrapper {

	private static final String RESOURCE_ROOT = "/org/zaproxy/zap/extension/scripts/resource/";
    private static Logger logger = Logger.getLogger(JavascriptEngineWrapper.class);

    private Map<String, String> templateMap = new HashMap<String, String>();

	public static final ImageIcon ICON = new ImageIcon(
			JavascriptEngineWrapper.class.getResource(RESOURCE_ROOT + "icons/cup.png"));

	public JavascriptEngineWrapper(ScriptEngine engine) {
		super(engine);
	}

	@Override
	public ImageIcon getIcon() {
		return ICON;
	}

	@Override
	public String getSyntaxStyle() {
		return SyntaxConstants.SYNTAX_STYLE_JAVASCRIPT;
	}

	@Override
	public String getTemplate(String type) {
		if (! templateMap.containsKey(type)) {
			templateMap.put(type, this.getStringReource("js/" + type.toLowerCase() + "-template.js"));
		}
		return templateMap.get(type);
	}
	
	private String getStringReource(String resourceName) {
		InputStream in = null;
		StringBuilder sb = new StringBuilder();
		try {
			in = this.getClass().getResourceAsStream(RESOURCE_ROOT + resourceName);
			if (in == null) {
				logger.error("Failed to find resource: " + resourceName);
				return "";
			}
			int numRead=0;
            byte[] buf = new byte[1024];
            while((numRead = in.read(buf)) != -1){
            	sb.append(new String(buf, 0, numRead));
            }
            return sb.toString();

		} catch (Exception e) {
			logger.error(e.getMessage(), e);
			return "";
		} finally {
			if (in != null) {
				try {
					in.close();
				} catch (IOException e) {
					// Ignore
				}
			}
		}
	}

	@Override
	public String getExtension() {
		return ".js";
	}

	@Override
	public boolean isTextBased() {
		return true;
	}

	@Override
	public boolean isRawEngine() {
		return false;
	}

}
