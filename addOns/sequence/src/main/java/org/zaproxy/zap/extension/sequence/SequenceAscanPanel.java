/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2015 The ZAP Development Team
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
package org.zaproxy.zap.extension.sequence;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.ascan.CustomScanPanel;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptCollection;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.model.StructuralNode;
import org.zaproxy.zap.model.StructuralSiteNode;
import org.zaproxy.zap.model.Target;

public class SequenceAscanPanel implements CustomScanPanel {

    private SequencePanel sequencePanel = null;
    public static final Logger logger = LogManager.getLogger(SequenceAscanPanel.class);

    private final ExtensionScript extensionScript;

    public SequenceAscanPanel(ExtensionScript extensionScript) {
        this.extensionScript = extensionScript;
    }

    @Override
    public Object[] getContextSpecificObjects() {
        List<ScriptWrapper> selectedIncludeScripts = getPanel(false).getSelectedIncludeScripts();

        if (!selectedIncludeScripts.isEmpty()) {
            return new Object[] {
                new ScriptCollection(
                        selectedIncludeScripts.get(0).getType(), selectedIncludeScripts)
            };
        }

        return null;
    }

    @Override
    public String getLabel() {
        return "sequence.custom.tab.title";
    }

    @Override
    public SequencePanel getPanel(boolean init) {
        if (sequencePanel == null || init) {
            sequencePanel = new SequencePanel(extensionScript);
        }
        return sequencePanel;
    }

    @Override
    public Target getTarget() {
        List<ScriptWrapper> selectedIncludeScripts = getPanel(false).getSelectedIncludeScripts();

        if (!selectedIncludeScripts.isEmpty()) {
            try {
                Session session = Model.getSingleton().getSession();
                List<StructuralNode> nodes = new ArrayList<>();
                for (ScriptWrapper sw : selectedIncludeScripts) {
                    Extension extZest =
                            Control.getSingleton()
                                    .getExtensionLoader()
                                    .getExtension("ExtensionZest");
                    if (extZest != null) {
                        Method method =
                                extZest.getClass()
                                        .getMethod("getAllRequestsInScript", ScriptWrapper.class);
                        @SuppressWarnings("unchecked")
                        List<HttpMessage> msgs = (List<HttpMessage>) method.invoke(extZest, sw);
                        for (HttpMessage msg : msgs) {
                            SiteNode node = session.getSiteTree().findNode(msg, false);
                            if (node == null) {
                                HistoryReference hr =
                                        new HistoryReference(
                                                session, HistoryReference.TYPE_TEMPORARY, msg);
                                node = session.getSiteTree().addPath(hr);
                            }
                            nodes.add(new StructuralSiteNode(node));
                        }
                    }
                }
                return new Target(nodes);
            } catch (Exception e) {
                logger.error(e.getMessage(), e);
            }
        }

        return null;
    }

    @Override
    public String validateFields() {
        // No validation needed
        return null;
    }
}
