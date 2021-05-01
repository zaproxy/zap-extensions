/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
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
package org.zaproxy.zap.extension.accessControl.widgets;

import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.model.SiteNode;
import org.zaproxy.zap.model.Context;

public class ContextSiteTree extends SiteTree {

    private static final Logger LOGGER = LogManager.getLogger(ContextSiteTree.class);

    public ContextSiteTree() {
        super(
                new SiteTreeNode(
                        Constant.messages.getString("accessControl.contextTree.root"), null));
    }

    public void reloadTree(Session session, Context context) {
        LOGGER.debug("Reloading tree for context: {}", context.getId());
        this.getRoot().removeAllChildren();
        List<SiteNode> contextNodes = session.getNodesInContextFromSiteTree(context);
        for (SiteNode node : contextNodes) {
            HistoryReference ref = node.getHistoryReference();
            if (ref != null) {
                this.addPath(context, ref.getURI(), ref.getMethod());
            }
        }
    }
}
