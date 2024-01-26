package org.zaproxy.zap.extension.pscanrulesBeta;

public interface CommonPassiveScanRuleInfo {
    public int getPluginId();

    public default String getHelpLink() {
        return "https://www.zaproxy.org/docs/desktop/addons/passive-scan-rules-beta/#id-"
                + getPluginId();
    }
}