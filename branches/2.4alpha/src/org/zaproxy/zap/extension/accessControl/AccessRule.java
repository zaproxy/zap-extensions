package org.zaproxy.zap.extension.accessControl;

import org.parosproxy.paros.Constant;

public enum AccessRule {
	ALLOWED(Constant.messages.getString("accessControl.accessRule.allowed")), DENIED(Constant.messages
			.getString("accessControl.accessRule.denied")), INHERIT(Constant.messages
			.getString("accessControl.accessRule.inherited")), UNKNOWN(Constant.messages
			.getString("accessControl.accessRule.unknown"));

	private final String localizedName;

	private AccessRule(String localizedName) {
		this.localizedName = localizedName;
	}

	@Override
	public String toString() {
		return localizedName;
	}
}
