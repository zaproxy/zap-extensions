/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2012 The ZAP development team
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
package org.zaproxy.zap.extension.scripts;

import org.parosproxy.paros.common.AbstractParam;

public class ScriptParam extends AbstractParam {

	private static final String PARAM_DEFAULT_SCRIPT = "script.defaultScript";
	private static final String PARAM_DEFAULT_DIR = "script.defaultDir";
	
	private String defaultScript = null;
	private String defaultDir = null;

	@Override
	protected void parse() {
		defaultScript = getConfig().getString(PARAM_DEFAULT_SCRIPT, "");
		defaultDir = getConfig().getString(PARAM_DEFAULT_DIR, "");
	}

	public String getDefaultScript() {
		return defaultScript;
	}

	public void setDefaultScript(String defaultScript) {
		this.defaultScript = defaultScript;
		getConfig().setProperty(PARAM_DEFAULT_SCRIPT, this.defaultScript);
	}

	public String getDefaultDir() {
		return defaultDir;
	}

	public void setDefaultDir(String defaultDir) {
		this.defaultDir = defaultDir;
		getConfig().setProperty(PARAM_DEFAULT_DIR, this.defaultDir);
	}

	
}
