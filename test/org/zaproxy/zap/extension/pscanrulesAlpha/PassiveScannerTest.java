/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP development team
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
package org.zaproxy.zap.extension.pscanrulesAlpha;

import java.util.ArrayList;
import java.util.List;

import net.htmlparser.jericho.Source;

import org.junit.Before;
import org.junit.BeforeClass;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.ScannerTestUtils;
import org.zaproxy.zap.extension.alert.ExtensionAlert;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

public abstract class PassiveScannerTest extends ScannerTestUtils {

	protected PluginPassiveScanner rule;
	protected PassiveScanThread parent;
	protected List<Alert> alertsRaised;

	@BeforeClass
	public static void beforeClass() {
		mockMessages(new ExtensionPscanRulesAlpha());
	}

	public PassiveScannerTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {
		alertsRaised = new ArrayList<>();
		parent = new PassiveScanThread(null, null, new ExtensionAlert()) {
			@Override
			public void raiseAlert(int arg0, Alert arg1) {
				alertsRaised.add(arg1);
			}
		};
		rule = createScanner();
		rule.setParent(parent);
	}

	protected abstract PluginPassiveScanner createScanner();

	protected Source createSource(HttpMessage msg) {
		return new Source(msg.getResponseHeader().toString() + msg.getResponseBody().toString());
	}

}