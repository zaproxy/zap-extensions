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

import java.io.File;
import java.io.OutputStreamWriter;
import java.util.ArrayList;
import java.util.List;

import net.htmlparser.jericho.Source;

import org.apache.commons.io.FileUtils;
import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.ConsoleAppender;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.PatternLayout;
import org.junit.After;
import org.junit.Before;
import org.mockito.Mockito;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.ScannerTestUtils;
import org.zaproxy.zap.extension.alert.ExtensionAlert;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;
import org.zaproxy.zap.utils.ClassLoaderUtil;

public abstract class PassiveScannerTest extends ScannerTestUtils {

	protected PluginPassiveScanner rule;
	protected PassiveScanThread parent;
	protected List<Alert> alertsRaised;
	
	private static final String INSTALL_PATH = "test/resources/install";
	private static final File HOME_DIR = new File("test/resources/home");

	public PassiveScannerTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {
		Constant.setZapInstall(INSTALL_PATH);
		HOME_DIR.mkdirs();
		Constant.setZapHome(HOME_DIR.getAbsolutePath());

		File langDir = new File(Constant.getZapInstall(), "lang");
		ClassLoaderUtil.addFile(langDir.getAbsolutePath());

		ExtensionLoader extLoader = Mockito.mock(ExtensionLoader.class);
		Control control = Mockito.mock(Control.class);
		Mockito.when(control.getExtensionLoader()).thenReturn(extLoader);

		// Init all the things
		Constant.getInstance();
		setUpMessages();
		Control.initSingletonForTesting();
		Model.getSingleton();
		
		alertsRaised = new ArrayList<>();
		parent = new PassiveScanThread(null, null, new ExtensionAlert(), null) {
			@Override
			public void raiseAlert(int arg0, Alert arg1) {
				alertsRaised.add(arg1);
			}
		};
		rule = createScanner();
		rule.setParent(parent);
	}
	
	/**
	 * Sets up the log to ease debugging.
	 */
	protected void setUpLog() {
		// Useful if you need to get some info when debugging
		BasicConfigurator.configure();
		ConsoleAppender ca = new ConsoleAppender();
		ca.setWriter(new OutputStreamWriter(System.out));
		ca.setLayout(new PatternLayout("%-5p [%t]: %m%n"));
		Logger.getRootLogger().addAppender(ca);
		Logger.getRootLogger().setLevel(Level.DEBUG);
	}
	
	protected void setUpMessages() {
		mockMessages(new ExtensionPscanRulesAlpha());
	}

	@After
	public void shutDown() throws Exception {
		FileUtils.deleteDirectory(HOME_DIR);
	}

	protected abstract PluginPassiveScanner createScanner();

	protected Source createSource(HttpMessage msg) {
		return new Source(msg.getResponseBody().toString());
	}

}