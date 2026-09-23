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
package org.zaproxy.zap.extension.websocket;

import org.zaproxy.zap.extension.script.ScriptEventListener;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.websocket.pscan.scripts.WebSocketScriptSynchronizer;

/**
 * Dispatches WebSocket Passive Rule script add/edit/remove events to a {@link
 * WebSocketScriptSynchronizer}, ignoring events for every other script type.
 */
class WebSocketPassiveScriptEventListener implements ScriptEventListener {

    private final WebSocketScriptSynchronizer synchronizer;

    WebSocketPassiveScriptEventListener(WebSocketScriptSynchronizer synchronizer) {
        this.synchronizer = synchronizer;
    }

    private static boolean isWebSocketPassiveScript(ScriptWrapper script) {
        return ExtensionWebSocket.SCRIPT_TYPE_WEBSOCKET_PASSIVE.equals(script.getType().getName());
    }

    @Override
    public void scriptAdded(ScriptWrapper script, boolean display) {
        if (isWebSocketPassiveScript(script)) {
            synchronizer.scriptAdded(script);
        }
    }

    @Override
    public void scriptChanged(ScriptWrapper script) {
        if (isWebSocketPassiveScript(script)) {
            synchronizer.scriptAdded(script);
        } else {
            // The script may have just been switched away from the WebSocket Passive type; drop
            // any rule synchronized for it under its previous type (a no-op otherwise).
            synchronizer.scriptRemoved(script);
        }
    }

    @Override
    public void scriptRemoved(ScriptWrapper script) {
        if (isWebSocketPassiveScript(script)) {
            synchronizer.scriptRemoved(script);
        }
    }

    @Override
    public void refreshScript(ScriptWrapper script) {
        // Nothing to do.
    }

    @Override
    public void preInvoke(ScriptWrapper script) {
        // Nothing to do.
    }

    @Override
    public void scriptError(ScriptWrapper script) {
        // Nothing to do.
    }

    @Override
    public void scriptSaved(ScriptWrapper script) {
        if (isWebSocketPassiveScript(script)) {
            synchronizer.scriptAdded(script);
        }
    }

    @Override
    public void templateAdded(ScriptWrapper script, boolean display) {
        // Nothing to do.
    }

    @Override
    public void templateRemoved(ScriptWrapper script) {
        // Nothing to do.
    }
}
