/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2013 The ZAP Development Team
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
package org.zaproxy.zap.extension.scripts;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.view.popup.ExtensionPopupMenuComponent;
import org.zaproxy.zap.view.popup.PopupMenuItemHttpMessageContainer;

@SuppressWarnings("serial")
public class InvokeScriptWithHttpMessageMenu extends PopupMenuItemHttpMessageContainer {

    private static final long serialVersionUID = 2282358266003940700L;
    private static Logger logger = LogManager.getLogger(InvokeScriptWithHttpMessageMenu.class);

    private ExtensionScriptsUI extension;
    private ScriptWrapper script;

    public InvokeScriptWithHttpMessageMenu(ExtensionScriptsUI extension, ScriptWrapper script) {
        super(script.getName(), true);
        this.extension = extension;
        this.script = script;
    }

    @Override
    public String getParentMenuName() {
        return Constant.messages.getString("scripts.runscript.popup");
    }

    @Override
    public boolean isSubMenu() {
        return true;
    }

    @Override
    public void performAction(HttpMessage msg) {
        logger.debug("Invoke script with {}", msg.getRequestHeader().getURI());
        // Execute in another thread to not occupy the EDT.
        new ScriptExecutorThread(extension, script, msg).start();
    }

    @Override
    public boolean isSafe() {
        return true;
    }

    @Override
    public void dismissed(ExtensionPopupMenuComponent selectedMenuComponent) {
        View.getSingleton().getPopupList().remove(this);
    }

    private static class ScriptExecutorThread extends Thread {

        private static final String BASE_NAME_SCRIPT_EXECUTOR_THREAD = "ZAP-ScriptExecutor-";

        private final ExtensionScriptsUI extension;
        private final ScriptWrapper script;
        private final HttpMessage message;

        public ScriptExecutorThread(
                ExtensionScriptsUI extension, ScriptWrapper script, HttpMessage message) {
            super();

            this.script = script;
            this.extension = extension;
            this.message = message;

            String name = script.getName();
            if (name.length() > 25) {
                name = name.substring(0, 25);
            }

            setName(BASE_NAME_SCRIPT_EXECUTOR_THREAD + name);
        }

        @Override
        public void run() {
            extension.invokeTargetedScript(script, message);
        }
    }
}
