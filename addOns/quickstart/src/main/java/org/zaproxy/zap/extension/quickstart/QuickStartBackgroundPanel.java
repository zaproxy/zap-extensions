/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
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
package org.zaproxy.zap.extension.quickstart;

import java.awt.Color;
import java.awt.GridBagLayout;
import javax.swing.UIManager;
import org.jdesktop.swingx.JXPanel;

/**
 * The base panel for quick start panels.
 *
 * <p>Uses a custom background colour.
 *
 * @see #getBackgroundColor()
 */
public class QuickStartBackgroundPanel extends JXPanel {

    private static final long serialVersionUID = 1L;

    private static Color backgroundColor;

    /**
     * Constructs a {@code QuickStartBackgroundPanel} with the custom colour and a {@link
     * GridBagLayout}.
     */
    public QuickStartBackgroundPanel() {
        super(new GridBagLayout());

        setBackground(getBackgroundColor());
    }

    /**
     * Gets the background colour that should be used by quick start panels and other components
     * displayed in them.
     *
     * @param force if true then reread the background colour from the UIManager
     * @return the custom background colour for quick start panels.
     */
    public static Color getBackgroundColor(boolean force) {
        if (backgroundColor == null || force) {
            backgroundColor = new Color(UIManager.getColor("TextField.background").getRGB());
        }
        return backgroundColor;
    }

    /**
     * Gets the background colour that should be used by quick start panels and other components
     * displayed in them.
     *
     * @return the custom background colour for quick start panels.
     */
    public static Color getBackgroundColor() {
        return getBackgroundColor(false);
    }

    @Override
    public void updateUI() {
        super.updateUI();
        setBackground(getBackgroundColor(true));
    }
}
