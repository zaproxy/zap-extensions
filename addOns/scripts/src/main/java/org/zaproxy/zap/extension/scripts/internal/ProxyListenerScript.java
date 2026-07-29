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
package org.zaproxy.zap.extension.scripts.internal;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.proxy.ProxyListener;
import org.parosproxy.paros.extension.history.ProxyListenerLog;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ProxyScript;
import org.zaproxy.zap.extension.script.ScriptsCache;
import org.zaproxy.zap.extension.script.ScriptsCache.CachedScript;
import org.zaproxy.zap.extension.script.ScriptsCache.Configuration;
import org.zaproxy.zap.extension.scripts.ExtensionScriptsUI;

public class ProxyListenerScript implements ProxyListener {

    // Should be the last one but one before the listener that saves the HttpMessage to the db
    // so that anything can be changed
    public static final int PROXY_LISTENER_ORDER = ProxyListenerLog.PROXY_LISTENER_ORDER - 2;

    private final ExtensionScript extension;
    private final ScriptsCache<ProxyScript> scripts;

    public ProxyListenerScript(ExtensionScript extension) {
        this.extension = extension;
        this.scripts =
                extension.createScriptsCache(
                        Configuration.<ProxyScript>builder()
                                .setScriptType(ExtensionScriptsUI.TYPE_PROXY)
                                .setTargetInterface(ProxyScript.class)
                                .setInterfaceErrorMessageProvider(
                                        sw ->
                                                Constant.messages.getString(
                                                        "scripts.interface.proxy.error"))
                                .build());
    }

    @Override
    public int getArrangeableListenerOrder() {
        return PROXY_LISTENER_ORDER;
    }

    @Override
    public boolean onHttpRequestSend(HttpMessage msg) {
        scripts.refresh();

        return invokeProxyScripts(msg, true);
    }

    private boolean invokeProxyScripts(HttpMessage msg, boolean request) {
        for (CachedScript<ProxyScript> cachedScript : scripts.getCachedScripts()) {
            try {
                boolean forwardMessage =
                        request
                                ? cachedScript.getScript().proxyRequest(msg)
                                : cachedScript.getScript().proxyResponse(msg);
                if (!forwardMessage) {
                    return false;
                }
            } catch (Exception e) {
                extension.handleScriptException(cachedScript.getScriptWrapper(), e);
            }
        }
        return true;
    }

    @Override
    public boolean onHttpResponseReceive(HttpMessage msg) {
        return invokeProxyScripts(msg, false);
    }
}
