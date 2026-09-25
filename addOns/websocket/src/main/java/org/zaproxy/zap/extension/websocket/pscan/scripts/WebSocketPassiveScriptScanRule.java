/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.websocket.pscan.scripts;

import java.util.Map;
import org.parosproxy.paros.control.Control;
import org.zaproxy.addon.commonlib.scanrules.ScanRuleMetadata;
import org.zaproxy.zap.control.AddOn;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.websocket.WebSocketMessageDTO;
import org.zaproxy.zap.extension.websocket.pscan.WebSocketPassiveScanner;
import org.zaproxy.zap.extension.websocket.pscan.WebSocketScanHelper;

/**
 * A {@link WebSocketPassiveScanner} backed by a single script that declares {@link
 * ScanRuleMetadata}, giving it its own stable id/name/status independent of the bundling {@link
 * ScriptsWebSocketPassiveScanner}.
 */
public class WebSocketPassiveScriptScanRule implements WebSocketPassiveScanner {

    private final ScriptWrapper script;
    private ScanRuleMetadata metadata;
    private ExtensionScript extScript;

    public WebSocketPassiveScriptScanRule(ScriptWrapper script, ScanRuleMetadata metadata) {
        this.script = script;
        this.metadata = metadata;
    }

    @Override
    public String getName() {
        return metadata.getName();
    }

    @Override
    public int getId() {
        return metadata.getId();
    }

    @Override
    public void scanMessage(WebSocketScanHelper helper, WebSocketMessageDTO webSocketMessage) {
        try {
            WebSocketPassiveScript s =
                    getExtScript().getInterface(script, WebSocketPassiveScript.class);
            if (s != null) {
                s.scan(helper, webSocketMessage);
            }
        } catch (Exception e) {
            getExtScript().handleScriptException(script, e);
        }
    }

    public AddOn.Status getStatus() {
        return metadata.getStatus();
    }

    public Map<String, String> getAlertTags() {
        return metadata.getAlertTags();
    }

    final ScriptWrapper getScript() {
        return script;
    }

    void setMetadata(ScanRuleMetadata metadata) {
        this.metadata = metadata;
    }

    private ExtensionScript getExtScript() {
        if (extScript == null) {
            extScript =
                    Control.getSingleton().getExtensionLoader().getExtension(ExtensionScript.class);
        }
        return extScript;
    }
}
