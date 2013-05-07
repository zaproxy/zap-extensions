package org.zaproxy.zap.extension.ascanrulesAlpha;

import java.util.ResourceBundle;

import org.parosproxy.paros.Constant;

public class AscanUtils {

	private static ResourceBundle messages = null;
	
	public static synchronized void registerI18N() {
		if (messages == null) {
			messages = ResourceBundle.getBundle(
	            AscanUtils.class.getPackage().getName() + ".Messages", Constant.getLocale());
			Constant.messages.addMessageBundle("ascanalpha", messages);
		}
	}
}
