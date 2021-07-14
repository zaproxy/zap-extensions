/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.addon.oast;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.addon.oast.base.OastServer;
import org.zaproxy.addon.oast.boast.BoastServer;
import org.zaproxy.addon.oast.callback.CallbackServer;
import org.zaproxy.addon.oast.ui.OastPanel;
import org.zaproxy.zap.extension.help.ExtensionHelp;

public class ExtensionOast extends ExtensionAdaptor {

    private static final String NAME = ExtensionOast.class.getSimpleName();

    private final Map<String, OastServer> servers = new HashMap<>();
    private OastParam param;
    private OastOptionsPanel oastOptionsPanel;
    private OastPanel oastPanel;

    public ExtensionOast() {
        super(NAME);
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);
        registerOastServer(new BoastServer());
        registerOastServer(new CallbackServer(this));
        extensionHook.addApiImplementor(new OastApi());
        extensionHook.addOptionsParamSet(getParam());
        getOastServers().values().forEach(t -> t.hook(extensionHook));
        if (hasView()) {
            extensionHook.getHookView().addStatusPanel(getOastPanel());
            extensionHook.getHookView().addOptionPanel(getOastOptionsPanel());
            ExtensionHelp.enableHelpKey(getOastPanel(), "ui.tabs.callbacks");
        }
    }

    @Override
    public void optionsLoaded() {
        getOastServers().values().forEach(OastServer::optionsLoaded);
    }

    @Override
    public void postInit() {
        getOastServers().values().forEach(OastServer::postInit);
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        super.unload();
        servers.values().forEach(this::unregisterOastServer);
    }

    @Override
    public boolean supportsDb(String type) {
        return true;
    }

    public void registerOastServer(OastServer server) {
        servers.put(server.getName(), server);
    }

    public void unregisterOastServer(OastServer server) {
        servers.remove(server.getName());
    }

    public Map<String, OastServer> getOastServers() {
        return Collections.unmodifiableMap(servers);
    }

    public void deleteAllCallbacks() {
        getOastServers().values().forEach(OastServer::deleteCallbacks);
    }

    OastParam getParam() {
        if (param == null) {
            param = new OastParam();
        }
        return param;
    }

    private OastOptionsPanel getOastOptionsPanel() {
        if (oastOptionsPanel == null) {
            oastOptionsPanel = new OastOptionsPanel(this);
        }
        return oastOptionsPanel;
    }

    public OastPanel getOastPanel() {
        if (oastPanel == null) {
            oastPanel = new OastPanel(this);
        }
        return oastPanel;
    }
}
