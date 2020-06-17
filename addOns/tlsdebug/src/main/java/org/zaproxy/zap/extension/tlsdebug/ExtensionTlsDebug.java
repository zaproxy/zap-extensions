/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP Development Team
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
package org.zaproxy.zap.extension.tlsdebug;

import java.io.IOException;
import java.net.URL;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.zap.extension.help.ExtensionHelp;

public class ExtensionTlsDebug extends ExtensionAdaptor {

    public static final String NAME = "ExtensionTlsDebug";

    private TlsDebugPanel tlsDebugPanel;

    public ExtensionTlsDebug() {
        super();
        this.setName(NAME);
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        if (getView() != null) {
            extensionHook.getHookView().addWorkPanel(getTlsDebugPanel());

            ExtensionHelp.enableHelpKey(getTlsDebugPanel(), "tlsdebug");
        }
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    private TlsDebugPanel getTlsDebugPanel() {
        if (tlsDebugPanel == null) {
            tlsDebugPanel = new TlsDebugPanel(this);
            tlsDebugPanel.setName(Constant.messages.getString("tlsdebug.panel.title"));
        }
        return tlsDebugPanel;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("tlsdebug.desc");
    }

    public void launchDebug(URL url) throws IOException {
        HttpsCallerLauncher pl = new HttpsCallerLauncher(this);
        pl.startProcess(url, this.getTlsDebugPanel().getDebugProperty());
    }

    public void notifyResponse(String line) {
        this.tlsDebugPanel.writeConsole(line);
    }
}
