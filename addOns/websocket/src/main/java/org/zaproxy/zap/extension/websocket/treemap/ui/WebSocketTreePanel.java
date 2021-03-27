/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2019 The ZAP Development Team
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
package org.zaproxy.zap.extension.websocket.treemap.ui;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.Rectangle;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTree;
import javax.swing.Scrollable;
import javax.swing.SwingUtilities;

public class WebSocketTreePanel extends JPanel {

    private static final long serialVersionUID = 1111011007687312311L;

    public WebSocketTreePanel(JTree webSocketTree, String scrollPaneName) {
        super(new BorderLayout());

        JScrollPane scrollPane = new JScrollPane();
        if (scrollPaneName != null) {
            scrollPane.setName(scrollPaneName);
        }

        JPanel panel = new ScrollableTreesPanel(webSocketTree);
        scrollPane.setViewportView(panel);

        add(scrollPane);
    }

    private static class ScrollableTreesPanel extends JPanel implements Scrollable {

        private static final long serialVersionUID = 2709986817434976954L;

        private final JTree websocketTree;

        public ScrollableTreesPanel(JTree websocketTree) {
            super(new BorderLayout());
            this.websocketTree = websocketTree;
            add(websocketTree, BorderLayout.CENTER);
        }

        @Override
        public Dimension getPreferredScrollableViewportSize() {
            Dimension dCT = websocketTree.getPreferredScrollableViewportSize();
            dCT.setSize(dCT.getWidth(), dCT.getHeight());
            return dCT;
        }

        @Override
        public int getScrollableUnitIncrement(
                Rectangle visibleRect, int orientation, int direction) {
            return websocketTree.getScrollableUnitIncrement(visibleRect, orientation, direction);
        }

        @Override
        public int getScrollableBlockIncrement(
                Rectangle visibleRect, int orientation, int direction) {
            // Same behaviour for both trees.
            return websocketTree.getScrollableBlockIncrement(visibleRect, orientation, direction);
        }

        @Override
        public boolean getScrollableTracksViewportWidth() {
            int width = websocketTree.getPreferredSize().width;
            return SwingUtilities.getUnwrappedParent(this).getWidth() > width;
        }

        @Override
        public boolean getScrollableTracksViewportHeight() {
            return SwingUtilities.getUnwrappedParent(this).getHeight()
                    > (websocketTree.getPreferredSize().height);
        }
    }
}
