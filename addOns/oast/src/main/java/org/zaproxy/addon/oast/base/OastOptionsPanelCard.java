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
package org.zaproxy.addon.oast.base;

import java.awt.GridBagLayout;
import javax.swing.BorderFactory;
import javax.swing.JPanel;
import javax.swing.border.TitledBorder;
import org.zaproxy.zap.utils.FontUtils;

public abstract class OastOptionsPanelCard extends JPanel {

    private static final long serialVersionUID = 1L;

    public OastOptionsPanelCard(OastServer oastServer) {
        setName(oastServer.getName());
        setLayout(new GridBagLayout());
        setBorder(
                BorderFactory.createTitledBorder(
                        null,
                        getName(),
                        TitledBorder.DEFAULT_JUSTIFICATION,
                        javax.swing.border.TitledBorder.DEFAULT_POSITION,
                        FontUtils.getFont(FontUtils.Size.standard)));
    }

    public abstract void initParam(Object obj);

    public abstract void saveParam(Object obj);
}
