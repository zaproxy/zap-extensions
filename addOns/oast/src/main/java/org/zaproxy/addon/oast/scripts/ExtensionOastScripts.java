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
package org.zaproxy.addon.oast.scripts;

import java.io.File;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.zaproxy.addon.oast.ExtensionOast;
import org.zaproxy.zap.extension.graaljs.ExtensionGraalJs;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptEngineWrapper;
import org.zaproxy.zap.extension.script.ScriptType;
import org.zaproxy.zap.extension.script.ScriptWrapper;

public class ExtensionOastScripts extends ExtensionAdaptor {

    private static final List<Class<? extends Extension>> DEPENDENCIES;
    private static final Logger LOGGER = LogManager.getLogger(ExtensionOastScripts.class);
    private static final String TEMPLATE_REGISTER_REQUEST_HANDLER = "OAST Request Handler.js";
    private static final String SCRIPT_GET_BOAST_SERVERS = "OAST Get BOAST Servers.js";
    private static final String SCRIPT_GET_INTERACTSH_PAYLOADS = "OAST Get Interactsh Payloads.js";

    private ExtensionScript extScript;

    static {
        List<Class<? extends Extension>> dependencies = new ArrayList<>(3);
        dependencies.add(ExtensionOast.class);
        dependencies.add(ExtensionScript.class);
        dependencies.add(ExtensionGraalJs.class);
        DEPENDENCIES = Collections.unmodifiableList(dependencies);
    }

    @Override
    public String getName() {
        return ExtensionOastScripts.class.getSimpleName();
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString("oast.scripts.name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("oast.scripts.desc");
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return DEPENDENCIES;
    }

    @Override
    public void postInit() {
        extScript = Control.getSingleton().getExtensionLoader().getExtension(ExtensionScript.class);
        addScripts();
    }

    @Override
    public void postInstall() {
        addTemplates();
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        removeScripts();
    }

    private void addTemplates() {
        addScript(
                TEMPLATE_REGISTER_REQUEST_HANDLER,
                Constant.messages.getString("oast.scripts.requestHandler.desc"),
                extScript.getScriptType("extender"),
                true);
    }

    private void addScripts() {
        addScript(
                SCRIPT_GET_BOAST_SERVERS,
                Constant.messages.getString("oast.scripts.getBoastServers.desc"),
                extScript.getScriptType(ExtensionScript.TYPE_STANDALONE),
                false);
        addScript(
                SCRIPT_GET_INTERACTSH_PAYLOADS,
                Constant.messages.getString("oast.scripts.getInteractshPayloads.desc"),
                extScript.getScriptType(ExtensionScript.TYPE_STANDALONE),
                false);
    }

    private void addScript(String name, String description, ScriptType type, boolean isTemplate) {
        try {
            if (extScript.getScript(name) != null) {
                return;
            }
            ScriptEngineWrapper engine = extScript.getEngineWrapper("Graal.js");
            if (engine == null) {
                return;
            }

            File file;
            if (isTemplate) {
                file =
                        Paths.get(
                                        Constant.getZapHome(),
                                        ExtensionScript.TEMPLATES_DIR,
                                        type.getName(),
                                        name)
                                .toFile();
            } else {
                file =
                        Paths.get(
                                        Constant.getZapHome(),
                                        ExtensionScript.SCRIPTS_DIR,
                                        ExtensionScript.SCRIPTS_DIR,
                                        type.getName(),
                                        name)
                                .toFile();
            }
            ScriptWrapper script = new ScriptWrapper(name, description, engine, type, true, file);
            extScript.loadScript(script);
            if (isTemplate) {
                extScript.addTemplate(script, false);
            } else {
                extScript.addScript(script, false);
            }
        } catch (Exception e) {
            LOGGER.warn(
                    Constant.messages.getString(
                            "oast.scripts.warn.couldNotAddScripts", e.getLocalizedMessage()));
        }
    }

    private void removeScripts() {
        if (extScript == null) {
            return;
        }
        removeScript(TEMPLATE_REGISTER_REQUEST_HANDLER, true);
        removeScript(SCRIPT_GET_BOAST_SERVERS, false);
    }

    private void removeScript(String name, boolean isTemplate) {
        ScriptWrapper script;
        if (isTemplate) {
            script = extScript.getTreeModel().getTemplate(name);
        } else {
            script = extScript.getScript(name);
        }

        if (script == null) {
            return;
        }

        if (isTemplate) {
            extScript.removeTemplate(script);
        } else {
            extScript.removeScript(script);
        }
    }
}
