package org.zaproxy.zap.extension.accessControl;

import org.parosproxy.paros.Constant;

public enum AccessRule {
	ALLOWED, DENIED, INHERIT, UNKNOWN;

	private static final String VALUE_ALLOWED = Constant.messages
			.getString("accessControl.accessRule.allowed");
	private static final String VALUE_DENIED = Constant.messages.getString("accessControl.accessRule.denied");
	private static final String VALUE_INHERITED = Constant.messages
			.getString("accessControl.accessRule.inherited");
	private static final String VALUE_UNKNOWN = Constant.messages
			.getString("accessControl.accessRule.unknown");

	public String getLocalizedString() {
		switch (this) {
		case ALLOWED:
			return VALUE_ALLOWED;
		case DENIED:
			return VALUE_DENIED;
		case INHERIT:
			return VALUE_INHERITED;
		default:
			return VALUE_UNKNOWN;
		}
	}
}
