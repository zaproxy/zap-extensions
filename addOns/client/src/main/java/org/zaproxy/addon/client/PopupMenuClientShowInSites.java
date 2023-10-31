/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.addon.client;

import java.awt.Component;
import java.awt.event.ActionEvent;
import java.util.List;
import org.apache.commons.httpclient.URI;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.view.View;

public class PopupMenuClientShowInSites extends PopupMenuItemClient {

    private static final long serialVersionUID = 1L;
    private static final Logger LOGGER = LogManager.getLogger(PopupMenuClientShowInSites.class);

    public PopupMenuClientShowInSites(ClientMapPanel clientMapPanel) {
        super(Constant.messages.getString("client.tree.popup.sites"), clientMapPanel);
    }

    @Override
    public void performAction(ActionEvent e) {
        ClientNode node = getClientMapPanel().getSelectedNode();

        try {
            SiteNode siteNode =
                    Model.getSingleton()
                            .getSession()
                            .getSiteTree()
                            .findNode(new URI(node.getUserObject().getUrl(), true));
            if (siteNode != null) {
                View.getSingleton().getSiteTreePanel().showInSites(siteNode);
                View.getSingleton()
                        .getWorkbench()
                        .getTabbedSelect()
                        .setSelectedComponent(View.getSingleton().getSiteTreePanel());
            }
        } catch (Exception e1) {
            LOGGER.error(e1.getMessage(), e1);
        }
    }

    @Override
    public boolean isEnableForComponent(Component invoker) {
        boolean enabled = super.isEnableForComponent(invoker);
        if (enabled) {
            // Disable for multiple nodes, root, and any nodes that have not been visited
            List<ClientNode> nodes = getClientMapPanel().getSelectedNodes();
            this.setEnabled(
                    nodes.size() == 1
                            && !nodes.get(0).isRoot()
                            && nodes.get(0).getUserObject().isVisited());
        }
        return enabled;
    }
}
