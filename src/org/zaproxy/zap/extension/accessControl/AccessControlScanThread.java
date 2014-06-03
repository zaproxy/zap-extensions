package org.zaproxy.zap.extension.accessControl;

import java.util.List;

import javax.swing.ListModel;

import org.fife.ui.rtextarea.RTextAreaEditorKit.SetReadOnlyAction;
import org.parosproxy.paros.model.SiteNode;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.scan.BaseScanStartOptions;
import org.zaproxy.zap.scan.BaseScannerThread;
import org.zaproxy.zap.users.User;

public class AccessControlScanThread extends BaseScannerThread<BaseScanStartOptions> {

	@Override
	public void reset() {
		setPaused(false);
		setRunning(false);
	}

	@Override
	public void pauseScan() {
		setPaused(true);
	}

	@Override
	public void resumeScan() {
		setPaused(false);
	}

	@Override
	public void startScan() {
		setRunning(true);
	}

	@Override
	public void stopScan() {
		setRunning(false);
	}

	public static class AccessControlScannerStartOptions extends BaseScanStartOptions {
		Context targetContext;
		List<User> targetUsers;
	}
}
