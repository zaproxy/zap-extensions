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
package org.zaproxy.zap.extension.mitmconf;

import java.net.MalformedURLException;
import java.net.URL;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.zap.extension.api.API;

public class ExtensionMitmConf extends ExtensionAdaptor  {

	private static final Logger logger = Logger.getLogger(ExtensionMitmConf.class);
	
	public static final String NAME = "ExtensionMitmConf";
	
	private MitmConfAPI api = new MitmConfAPI();

	public ExtensionMitmConf() {
		super();
		initialize();
	}

	private void initialize() {
        this.setName(NAME);
        this.setOrder(101);
	}

	@Override
	public void hook(ExtensionHook extensionHook) {
		API.getInstance().registerApiImplementor(api);
	}
	
	@Override
	public String getAuthor() {
		return Constant.ZAP_TEAM;
	}

	@Override
	public String getDescription() {
		return "TODO"; // TODO: Constant.messages.getString("reveal.desc");
	}

	@Override
	public URL getURL() {
		try {
			return new URL(Constant.ZAP_HOMEPAGE);
		} catch (MalformedURLException e) {
			return null;
		}
	}
}
