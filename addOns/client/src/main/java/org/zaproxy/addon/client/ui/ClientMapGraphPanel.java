/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.addon.client.ui;

import com.mxgraph.layout.hierarchical.mxHierarchicalLayout;
import com.mxgraph.swing.mxGraphComponent;
import com.mxgraph.view.mxGraph;
import java.awt.BorderLayout;
import java.util.HashMap;
import java.util.Map;
import javax.swing.SwingConstants;
import org.jgrapht.Graph;
import org.jgrapht.graph.DefaultEdge;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.AbstractPanel;
import org.zaproxy.addon.client.ExtensionClientIntegration;
import org.zaproxy.addon.client.internal.ClientSideComponent;
import org.zaproxy.addon.client.internal.InteractableState;
import org.zaproxy.addon.client.internal.graph.ClientGraphVertex;

@SuppressWarnings("serial")
public class ClientMapGraphPanel extends AbstractPanel {

    private static final long serialVersionUID = 1L;

    private static final String URL_STYLE =
            "fillColor=#D4E6F1;strokeColor=#2E86C1;rounded=1;whiteSpace=wrap;";
    private static final String COMPONENT_STYLE =
            "fillColor=#D5F5E3;strokeColor=#28B463;rounded=1;whiteSpace=wrap;";
    private static final String COMPONENT_STATE_INTERACTABLE_STYLE =
            "fillColor=#F0B27A;strokeColor=#CA6F1E;rounded=1;whiteSpace=wrap;";
    private static final String COMPONENT_STATE_NON_INTERACTABLE_STYLE =
            "fillColor=#FDEBD0;strokeColor=#E59866;rounded=1;whiteSpace=wrap;";

    private static final int VERTEX_HEIGHT = 30;
    private static final int CHAR_WIDTH = 7;
    private static final int VERTEX_PADDING = 20;

    private final mxGraph visualGraph;
    private final mxGraphComponent graphComponent;

    public ClientMapGraphPanel() {
        super();
        setLayout(new BorderLayout());
        setName(Constant.messages.getString(ExtensionClientIntegration.PREFIX + ".graph.title"));
        setIcon(ExtensionClientIntegration.getIcon("application-browser.png"));

        visualGraph =
                new mxGraph() {
                    @Override
                    public String getToolTipForCell(Object cell) {
                        if (model.isVertex(cell)) {
                            return String.valueOf(model.getValue(cell));
                        }
                        return "";
                    }
                };
        visualGraph.setEdgeLabelsMovable(false);
        visualGraph.setCellsEditable(false);
        visualGraph.setCellsResizable(false);
        visualGraph.setAllowDanglingEdges(false);

        graphComponent = new mxGraphComponent(visualGraph);
        graphComponent.setConnectable(false);
        graphComponent.setToolTips(true);
        graphComponent.setAutoExtend(true);
        graphComponent.setAutoScroll(true);

        add(graphComponent, BorderLayout.CENTER);
    }

    public void refresh(Graph<ClientGraphVertex, DefaultEdge> jgraphtGraph) {
        Object parent = visualGraph.getDefaultParent();
        visualGraph.getModel().beginUpdate();
        try {
            visualGraph.removeCells(visualGraph.getChildCells(parent, true, true));

            Map<ClientGraphVertex, Object> vertexMap = new HashMap<>();

            synchronized (jgraphtGraph) {
                for (ClientGraphVertex vertex : jgraphtGraph.vertexSet()) {
                    String label;
                    String style;

                    if (vertex instanceof ClientGraphVertex.Url urlVertex) {
                        label = urlVertex.url();
                        style = URL_STYLE;
                    } else if (vertex instanceof ClientGraphVertex.Component compVertex) {
                        ClientSideComponent comp = compVertex.component();
                        label = comp.getTypeForDisplay();
                        String text = comp.getText();
                        if (text != null && !text.isEmpty()) {
                            label += ": " + text;
                        }
                        InteractableState ws = compVertex.state();
                        if (ws == null) {
                            style = COMPONENT_STYLE;
                        } else if (ws.isVisible() && ws.isEnabled()) {
                            style = COMPONENT_STATE_INTERACTABLE_STYLE;
                        } else {
                            style = COMPONENT_STATE_NON_INTERACTABLE_STYLE;
                        }
                    } else {
                        continue;
                    }

                    int width = Math.max(label.length() * CHAR_WIDTH + VERTEX_PADDING, 60);
                    Object cell =
                            visualGraph.insertVertex(
                                    parent, null, label, 0, 0, width, VERTEX_HEIGHT, style);
                    vertexMap.put(vertex, cell);
                }

                for (DefaultEdge edge : jgraphtGraph.edgeSet()) {
                    ClientGraphVertex source = jgraphtGraph.getEdgeSource(edge);
                    ClientGraphVertex target = jgraphtGraph.getEdgeTarget(edge);
                    Object sourceCell = vertexMap.get(source);
                    Object targetCell = vertexMap.get(target);
                    if (sourceCell != null && targetCell != null) {
                        visualGraph.insertEdge(parent, null, null, sourceCell, targetCell);
                    }
                }
            }

            mxHierarchicalLayout layout =
                    new mxHierarchicalLayout(visualGraph, SwingConstants.WEST);
            layout.execute(parent);
        } finally {
            visualGraph.getModel().endUpdate();
        }
    }

    public void clear() {
        Object parent = visualGraph.getDefaultParent();
        visualGraph.getModel().beginUpdate();
        try {
            visualGraph.removeCells(visualGraph.getChildCells(parent, true, true));
        } finally {
            visualGraph.getModel().endUpdate();
        }
    }
}
