package org.zaproxy.zap.extension.accessControl;

import java.util.LinkedList;
import java.util.List;

import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.scan.BaseContextScannerThread;
import org.zaproxy.zap.scan.ScanStartOptions;
import org.zaproxy.zap.users.User;

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

	public static class AccessControlScanStartOptions implements ScanStartOptions {
		Context targetContext;
		List<User> targetUsers;

		public AccessControlScanStartOptions() {
			super();
			this.targetUsers = new LinkedList<User>();
		}

	}
}
