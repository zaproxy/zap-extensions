package org.zaproxy.zap.extension.pscanrulesBeta;

import java.util.ResourceBundle;

import org.parosproxy.paros.Constant;

public class PscanUtils {

	private static ResourceBundle messages = null;
	
	public static synchronized void registerI18N() {
		if (messages == null) {
			messages = ResourceBundle.getBundle(
	            PscanUtils.class.getPackage().getName() + ".Messages", Constant.getLocale());
			Constant.messages.addMessageBundle("pscanbeta", messages);
		}
	}
}
