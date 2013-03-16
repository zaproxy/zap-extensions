package org.zaproxy.zap.extension.pscanrulesAlpha;

import java.util.ResourceBundle;

import org.parosproxy.paros.Constant;

public final class PscanUtils {

	private static ResourceBundle messages = null;
	
	private PscanUtils() {
	}
	
	public static synchronized void registerI18N() {
		if (messages == null) {
			messages = ResourceBundle.getBundle(
					PscanUtils.class.getPackage().getName() + ".Messages", Constant.getLocale());
			Constant.messages.addMessageBundle("pscanalpha", messages);
		}
	}
}
