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
package org.zaproxy.zap.extension.accessControl;

import java.util.LinkedList;
import java.util.List;

import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.scan.BaseContextScannerThread;
import org.zaproxy.zap.scan.ScanStartOptions;
import org.zaproxy.zap.users.User;

/**
 * The scanner thread used to test access control issues. Requires
 * {@link AccessControlScanStartOptions} for specifying the scan options.
 * 
 * @see ExtensionAccessControl
 * @see AccessControlScanStartOptions
 */
public class AccessControlScannerThread extends BaseContextScannerThread<ScanStartOptions> {

	public AccessControlScannerThread(int contextId) {
		super(contextId);
	}

	@Override
	protected void scan() {
		setScanMaximumProgress(10);
		setRunning(true);
		notifyScanStarted();
		for (int i = 1; i <= 10; i++) {
			setScanProgress(i);

			// Do the actual work
			try {
				Thread.sleep(500 + i * 20);
			} catch (InterruptedException e) {
				e.printStackTrace();
			}

			// Check if it's stopped
			if (!isRunning())
				break;

			// Check if it's paused
			while (isPaused()) {
				try {
					Thread.sleep(100);
				} catch (InterruptedException e) {
					e.printStackTrace();
				}
			}
		}
		setRunning(false);
		notifyScanFinished();
	}

	/**
	 * The scan options for the {@link AccessControlScannerThread} performing access control
	 * testing.
	 */
	public static class AccessControlScanStartOptions implements ScanStartOptions {
		Context targetContext;
		List<User> targetUsers;

		public AccessControlScanStartOptions() {
			super();
			this.targetUsers = new LinkedList<User>();
		}

	}
}
