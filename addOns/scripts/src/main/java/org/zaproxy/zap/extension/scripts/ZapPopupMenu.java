/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2017 The ZAP Development Team
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

import java.awt.Component;
import javax.swing.JPopupMenu;
import org.parosproxy.paros.view.View;

public class ZapPopupMenu extends JPopupMenu {

    public static final ZapPopupMenu INSTANCE = new ZapPopupMenu();

    private static final long serialVersionUID = -3110110234622733751L;

    private ZapPopupMenu() {}

    @Override
    public void show(Component invoker, int x, int y) {
        View.getSingleton().getPopupMenu().show(invoker, x, y);
    }
}
