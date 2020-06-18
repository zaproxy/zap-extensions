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
package org.zaproxy.zap.extension.callgraph;

import com.mxgraph.layout.hierarchical.mxHierarchicalLayout;
import com.mxgraph.model.mxCell;
import com.mxgraph.model.mxGeometry;
import com.mxgraph.model.mxGraphModel;
import com.mxgraph.swing.handler.mxRubberband;
import com.mxgraph.swing.mxGraphComponent;
import com.mxgraph.swing.mxGraphOutline;
import com.mxgraph.view.mxGraph;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Rectangle;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseEvent;
import java.security.InvalidParameterException;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.SwingConstants;
import org.apache.commons.httpclient.URI;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.db.Database;
import org.parosproxy.paros.db.paros.ParosDatabase;
import org.parosproxy.paros.db.paros.ParosDatabaseServer;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.view.AbstractFrame;

/**
 * displays a call graph
 *
 * @author 70pointer@gmail.com
 */
public class CallGraphFrame extends AbstractFrame {

    private static final long serialVersionUID = 6666666666666666666L;

    private static final Logger log = Logger.getLogger(CallGraphFrame.class);
    private FontMetrics fontmetrics = null;
    private mxGraph graph =
            new mxGraph() {
                @Override
                public String getToolTipForCell(Object cell) {
                    if (model.isEdge(cell)) {
                        // the value is truncated, so get the id, which is the full URL instead
                        mxCell cellSource = (mxCell) model.getTerminal(cell, true);
                        mxCell cellTarget = (mxCell) model.getTerminal(cell, false);
                        return cellSource.getId() + " --> " + cellTarget.getId();
                    } else if (model.isVertex(cell)) {
                        mxCell cellVertex = (mxCell) cell;
                        return cellVertex.getId();
                    } else return "Unknown cell type";
                }
            };
    Object parent = graph.getDefaultParent();

    public CallGraphFrame(Pattern urlPattern) {
        // visibility needs to be temporarily set, so we can get the font metrics
        this.setVisible(true);
        Graphics graphics = this.getGraphics();
        Font font = graphics.getFont();
        this.fontmetrics = graphics.getFontMetrics(font);
        this.setVisible(false);

        // now retrieve the call Graph data
        try {
            setupGraph(urlPattern);
            setupFrame();
        } catch (SQLException e) {
            log.error("Failed to setup the graph", e);
        }
    }

    /**
     * sets up the graph by retrieving the nodes and edges from the history table in the database
     *
     * @param urlPattern
     * @throws SQLException
     */
    private void setupGraph(Pattern urlPattern) throws SQLException {
        Connection conn = null;
        Statement st = null;
        ResultSet rs = null;
        Map<String, String> schemaAuthorityToColor = new HashMap<String, String>();
        // use some web safe colours. Currently, there are 24 colours.
        String[] colors = {
            "#FFFF00", "#FFCC00", "#FF9900", "#FF6600", "#FF3300", "#CCFF00", "#CCCC00", "#CC9900",
            "#CC6600", "#99FF00", "#999900", "#996600", "#CCFFCC", "#CCCCCC", "#99CCCC", "#9999CC",
            "#9966CC", "#66FFCC", "#6699CC", "#6666CC", "#33FFCC", "#33CCCC", "#3399CC", "#00FFCC"
        };
        int colorsUsed = 0;
        try {
            // Create a pattern for the specified

            // get a new connection to the database to query it, since the existing database classes
            // do not cater for
            // ad-hoc queries on the table
            /*
             * TODO Add-ons should NOT make their own connections to the db any more - the db layer is plugable
             * so could be implemented in a completely different way
             * TODO: how? There is currently no API to do this.
             */
            // Note: the db is a singleton instance, so do *not* close it!!
            Database db = Model.getSingleton().getDb();
            if (!(db instanceof ParosDatabase)) {
                throw new InvalidParameterException(db.getClass().getCanonicalName());
            }

            conn = ((ParosDatabaseServer) db.getDatabaseServer()).getNewConnection();

            // we begin adding stuff to the graph, so begin a "transaction" on it.
            // we will close this after we add all the vertexes and edges to the graph
            graph.getModel().beginUpdate();

            // prepare to add the vertices to the graph
            // this must include all URLs references as vertices, even if those URLs did not feature
            // in the history table in their own right

            // include entries of type 1 (proxied), 2 (spidered), 10 (Ajax spidered) from the
            // history
            st = conn.createStatement();
            rs =
                    st.executeQuery(
                            "select distinct URI from HISTORY where histtype in (1,2,10) union distinct select distinct  RIGHT(REGEXP_SUBSTRING (REQHEADER, 'Referer:.+') , LENGTH(REGEXP_SUBSTRING (REQHEADER, 'Referer:.+'))-LENGTH('Referer: ')) from HISTORY where REQHEADER like '%Referer%' and histtype in (1,2,10) order by 1");
            for (; rs.next(); ) {
                String url = rs.getString(1);

                // remove urls that do not match the pattern specified (all sites / one site)
                Matcher urlmatcher = urlPattern.matcher(url);
                if (urlmatcher.find()) {
                    // addVertex(url , url);
                    try {
                        URI uri = new URI(url, false);
                        String schemaAuthority = uri.getScheme() + "://" + uri.getAuthority();
                        String path = uri.getPathQuery();
                        if (path == null) path = "/";
                        String color = schemaAuthorityToColor.get(schemaAuthority);
                        if (color == null) {
                            // not found already.. so assign this scheme and authority a color.
                            if (colorsUsed >= colors.length) {
                                throw new Exception(
                                        "Too many scheme/authority combinations. Ne need more colours");
                            }
                            color = colors[colorsUsed++];
                            schemaAuthorityToColor.put(schemaAuthority, color);
                        }
                        addVertex(path, url, "fillColor=" + color);
                    } catch (Exception e) {
                        log.error("Error graphing node for URL " + url, e);
                    }
                } else {
                    if (log.isDebugEnabled())
                        log.debug(
                                "URL "
                                        + url
                                        + " does not match the specified pattern "
                                        + urlPattern
                                        + ", so not adding it as a vertex");
                }
            }
            // close the resultset and statement
            rs.close();
            st.close();

            // set up the edges in the graph
            st = conn.createStatement();
            rs =
                    st.executeQuery(
                            "select distinct RIGHT(REGEXP_SUBSTRING (REQHEADER, 'Referer:.+') , LENGTH(REGEXP_SUBSTRING (REQHEADER, 'Referer:.+'))-LENGTH('Referer: ')), URI from HISTORY where REQHEADER like '%Referer%' and histtype in (1,2,10) order by 2");

            mxGraphModel graphmodel = (mxGraphModel) graph.getModel();
            for (; rs.next(); ) {
                String predecessor = rs.getString(1);
                String url = rs.getString(2);

                // now trim back all urls from the base url
                // Matcher predecessorurlmatcher = urlpattern.matcher(predecessor);
                // if (predecessorurlmatcher.find()) {
                //	predecessor =  predecessorurlmatcher.group(1);
                //	}
                // Matcher urlmatcher = urlpattern.matcher(url);
                // if (urlmatcher.find()) {
                //	url =  urlmatcher.group(1);
                //	}

                // remove urls that do not match the pattern specified (all sites / one site)
                Matcher urlmatcher1 = urlPattern.matcher(predecessor);
                if (!urlmatcher1.find()) {
                    if (log.isDebugEnabled())
                        log.debug(
                                "Predecessor URL "
                                        + predecessor
                                        + " does not match the specified pattern "
                                        + urlPattern
                                        + ", so not adding it as a vertex");
                    continue; // to the next iteration
                }
                Matcher urlmatcher2 = urlPattern.matcher(url);
                if (!urlmatcher2.find()) {
                    if (log.isDebugEnabled())
                        log.debug(
                                "URL "
                                        + url
                                        + " does not match the specified pattern "
                                        + urlPattern
                                        + ", so not adding it as a vertex");
                    continue; // to the next iteration
                }

                // check that we have added the url as a vertex in its own right.. definitely should
                // have happened..
                mxCell predecessorVertex = (mxCell) graphmodel.getCell(predecessor);
                mxCell postdecessorVertex = (mxCell) graphmodel.getCell(url);
                if (predecessorVertex == null || postdecessorVertex == null) {
                    log.warn(
                            "Could not find graph node for "
                                    + predecessor
                                    + " or for "
                                    + url
                                    + ". Ignoring it.");
                    continue;
                }
                // add the edge (ie, add the dependency between 2 URLs)
                graph.insertEdge(
                        parent,
                        predecessorVertex.getId() + "-->" + postdecessorVertex.getId(),
                        null,
                        predecessorVertex,
                        postdecessorVertex);
            }

            // once all the vertices and edges are drawn, look for root nodes (nodes with no
            // incoming edges)
            // we will display the full URl for these, rather than just the path, to aid viewing the
            // graph
            Object[] vertices = graph.getChildVertices(graph.getDefaultParent());
            for (Object vertex : vertices) {
                Object[] incomingEdgesForVertex = graph.getIncomingEdges(vertex);
                if (incomingEdgesForVertex == null
                        || (incomingEdgesForVertex != null && incomingEdgesForVertex.length == 0)) {
                    // it's a root node. Set it's value (displayed label) to the same as it's id
                    // (the full URL)
                    mxCell vertextCasted = (mxCell) vertex;
                    vertextCasted.setValue(vertextCasted.getId());

                    // now sort out the text metrics for the vertex, since the size of the displayed
                    // text has been changed
                    Dimension textsize =
                            this.getTextDimension(
                                    (String) vertextCasted.getValue(), this.fontmetrics);
                    mxGeometry cellGeometry = vertextCasted.getGeometry();
                    cellGeometry.setHeight(textsize.getHeight());
                    cellGeometry.setWidth(textsize.getWidth());
                    vertextCasted.setGeometry(cellGeometry);
                }
            }
        } catch (SQLException e) {
            log.error("Error trying to setup the graph", e);
            throw e;
        } finally {

            if (rs != null && !rs.isClosed()) rs.close();
            if (st != null && !st.isClosed()) st.close();
            if (conn != null && !conn.isClosed()) conn.close();
            // mark the "transaction" on the graph as complete
            graph.getModel().endUpdate();
        }
    }

    private void setupFrame() {
        // define a visual layout on the graph
        mxHierarchicalLayout layout =
                new com.mxgraph.layout.hierarchical.mxHierarchicalLayout(
                        graph, SwingConstants.WEST);

        final mxGraphComponent graphComponent = new mxGraphComponent(graph);
        graphComponent.setConnectable(false);
        graphComponent.setToolTips(true);
        graphComponent.setAutoExtend(true);
        graphComponent.setAutoScroll(true);

        // add the graph component to the frame in the centre.
        getContentPane().add(graphComponent, BorderLayout.CENTER);

        // and set up a panel below that
        JPanel toolBar = new JPanel();
        toolBar.setLayout(new BorderLayout());
        // with an outline of the graph, and have it settle in the west..
        final mxGraphOutline graphOutline = new mxGraphOutline(graphComponent);
        graphOutline.setPreferredSize(new Dimension(100, 100));
        toolBar.add(graphOutline, BorderLayout.WEST);

        // and some buttons in the panel
        JPanel buttonBar = new JPanel();
        buttonBar.setLayout(new FlowLayout());

        // zoom to fit button
        JButton btZoomToFit = new JButton(Constant.messages.getString("callgraph.button.zoomfit"));
        btZoomToFit.addActionListener(
                new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent arg0) {
                        double newScale = 1;
                        Dimension graphSize = graphComponent.getGraphControl().getSize();
                        Dimension viewPortSize = graphComponent.getViewport().getSize();
                        int gw = (int) graphSize.getWidth();
                        int gh = (int) graphSize.getHeight();
                        if (gw > 0 && gh > 0) {
                            int w = (int) viewPortSize.getWidth();
                            int h = (int) viewPortSize.getHeight();

                            newScale = Math.min((double) w / gw, (double) h / gh);
                        }
                        graphComponent.zoomTo(newScale, true);
                    }
                });
        buttonBar.add(btZoomToFit);

        // center graph
        JButton btCenter = new JButton(Constant.messages.getString("callgraph.button.centregraph"));
        btCenter.addActionListener(
                new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent arg0) {
                        Dimension graphSize = graphComponent.getGraphControl().getSize();
                        Dimension viewPortSize = graphComponent.getViewport().getSize();
                        int x = graphSize.width / 2 - viewPortSize.width / 2;
                        int y = graphSize.height / 2 - viewPortSize.height / 2;
                        int w = viewPortSize.width;
                        int h = viewPortSize.height;
                        graphComponent
                                .getGraphControl()
                                .scrollRectToVisible(new Rectangle(x, y, w, h));
                    }
                });
        buttonBar.add(btCenter);

        // add a rubberband zoom on the mouse selection event
        new mxRubberband(graphComponent) {

            @Override
            public void mouseReleased(MouseEvent e) {
                // get bounds before they are reset
                Rectangle rect = bounds;
                // invoke usual behaviour
                super.mouseReleased(e);

                if (rect != null) {

                    double newScale = 1;
                    Dimension graphSize = new Dimension(rect.width, rect.height);
                    Dimension viewPortSize = graphComponent.getViewport().getSize();
                    int gw = (int) graphSize.getWidth();
                    int gh = (int) graphSize.getHeight();
                    if (gw > 0 && gh > 0) {
                        int w = (int) viewPortSize.getWidth();
                        int h = (int) viewPortSize.getHeight();
                        newScale = Math.min((double) w / gw, (double) h / gh);
                    }
                    // zoom to fit the selected area on screen
                    graphComponent.zoom(newScale);
                    // make the selected area visible
                    graphComponent
                            .getGraphControl()
                            .scrollRectToVisible(
                                    new Rectangle(
                                            (int) (rect.x * newScale),
                                            (int) (rect.y * newScale),
                                            (int) (rect.width * newScale),
                                            (int) (rect.height * newScale)));
                }
            }
        };

        // put the components on frame
        toolBar.add(buttonBar, BorderLayout.CENTER);
        getContentPane().add(toolBar, BorderLayout.SOUTH);

        // TODO: Do we need this here?
        // frame.setVisible(true);

        // lay it out
        graph.getModel().beginUpdate();
        try {
            layout.execute(graph.getDefaultParent());
        } finally {
            graph.getModel().endUpdate();
        }

        // setDefaultCloseOperation(JFrame.);
        // setSize(400, 400);
        pack();
        setVisible(true);
    }

    public Dimension getTextDimension(String text, FontMetrics metrics) {
        int hgt = metrics.getHeight();
        int adv = metrics.stringWidth(text);
        Dimension size = new Dimension(adv + 5, hgt + 5);
        return size;
    }

    public Object addVertex(String vertexName, String id, String style) {
        Dimension textsize = this.getTextDimension(vertexName, this.fontmetrics);
        Object ob =
                this.graph.insertVertex(
                        this.parent, id, vertexName, 0, 0, textsize.width, textsize.height, style);

        return ob;
    }
}
