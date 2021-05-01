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
package org.zaproxy.zap.extension.viewstate;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import javax.swing.BoxLayout;
import javax.swing.JFormattedTextField;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.ScrollPaneConstants;
import org.apache.commons.configuration.FileConfiguration;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.httppanel.Message;
import org.zaproxy.zap.extension.httppanel.view.AbstractByteHttpPanelViewModel;
import org.zaproxy.zap.extension.httppanel.view.HttpPanelView;
import org.zaproxy.zap.extension.httppanel.view.HttpPanelViewModel;
import org.zaproxy.zap.extension.httppanel.view.HttpPanelViewModelEvent;
import org.zaproxy.zap.extension.httppanel.view.HttpPanelViewModelListener;
import org.zaproxy.zap.extension.httppanel.view.hex.HttpPanelHexModel;
import org.zaproxy.zap.extension.viewstate.ViewStateModel.ViewStateUpdatedListener;
import org.zaproxy.zap.extension.viewstate.zap.utils.ASPViewState;
import org.zaproxy.zap.extension.viewstate.zap.utils.JSFViewState;
import org.zaproxy.zap.extension.viewstate.zap.utils.ViewState;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.utils.FontUtils;

public class HttpPanelViewStateView
        implements HttpPanelView, HttpPanelViewModelListener, ViewStateUpdatedListener {

    public static final String NAME = "HttpPanelViewStateView";
    private static final String CAPTION_NAME =
            Constant.messages.getString("viewstate.panel.caption");
    private static Logger logger = LogManager.getLogger(ExtensionHttpPanelViewStateView.class);
    private HttpPanelHexModel httpPanelHexModel = null;
    private JTable hexTableBody = null;
    private JPanel container = null;
    private JFormattedTextField vsInfoTxt = null;
    private javax.swing.JScrollPane scrollHexTableBody = null;
    private boolean isEditable = false;
    private AbstractByteHttpPanelViewModel model;
    private boolean isEnabled = true;

    public HttpPanelViewStateView(AbstractByteHttpPanelViewModel model, boolean isEditable) {
        this.model = model;
        getHttpPanelHexModel().setEditable(isEditable);
        // Register listener on the view
        ((ViewStateModel) model).setListener(this);
        this.model.addHttpPanelViewModelListener(this);
    }

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public String getCaptionName() {
        return CAPTION_NAME;
    }

    @Override
    public String getTargetViewName() {
        return "";
    }

    @Override
    public int getPosition() {
        return 0;
    }

    @Override
    public JScrollPane getPane() {
        if (scrollHexTableBody == null) {
            scrollHexTableBody = new javax.swing.JScrollPane();
            scrollHexTableBody.setName(CAPTION_NAME);
            scrollHexTableBody.setViewportView(getContainerPanel());
            scrollHexTableBody.setVerticalScrollBarPolicy(
                    ScrollPaneConstants.VERTICAL_SCROLLBAR_NEVER);
        }
        return scrollHexTableBody;
    }

    private JPanel getContainerPanel() {
        if (container == null) {
            container = new JPanel();
            container.setLayout(new BoxLayout(container, BoxLayout.PAGE_AXIS));
            JScrollPane cScroll = new JScrollPane();
            cScroll.setName(CAPTION_NAME);
            cScroll.setViewportView(getHexTableBody());
            // Outer scroll size constraints
            container.setPreferredSize(new Dimension(0, 100));
            // Setup text field for ViewState info
            vsInfoTxt = new JFormattedTextField();
            vsInfoTxt.setEditable(false);
            vsInfoTxt.setBackground(Color.decode("#D6D9DF"));
            vsInfoTxt.setFont(FontUtils.getFont("Courier", Font.BOLD));
            // Add to container
            container.add(cScroll);
            container.add(vsInfoTxt);
        }
        return container;
    }

    private JTable getHexTableBody() {
        if (hexTableBody == null) {
            hexTableBody = new JTable();
            hexTableBody.setName("");
            hexTableBody.setModel(getHttpPanelHexModel());

            hexTableBody.setGridColor(java.awt.Color.gray);
            hexTableBody.setIntercellSpacing(new java.awt.Dimension(1, 1));
            hexTableBody.setRowHeight(DisplayUtils.getScaledSize(18));

            hexTableBody.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
            hexTableBody.getColumnModel().getColumn(0).setPreferredWidth(100);
            for (int i = 1; i <= 17; i++) {
                hexTableBody.getColumnModel().getColumn(i).setPreferredWidth(30);
            }
            for (int i = 17; i <= hexTableBody.getColumnModel().getColumnCount() - 1; i++) {
                hexTableBody.getColumnModel().getColumn(i).setPreferredWidth(25);
            }

            hexTableBody.setCellSelectionEnabled(true);
            hexTableBody.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        }
        return hexTableBody;
    }

    public HttpPanelHexModel getHttpPanelHexModel() {
        if (httpPanelHexModel == null) {
            httpPanelHexModel = new HttpPanelHexModel();
        }
        return httpPanelHexModel;
    }

    public void setEnabled(boolean enabled) {
        isEnabled = enabled;
    }

    @Override
    public boolean isEnabled(Message aMessage) {
        return isEnabled;
    }

    @Override
    public boolean hasChanged() {
        return getHttpPanelHexModel().hasChanged();
    }

    @Override
    public boolean isEditable() {
        return isEditable;
    }

    @Override
    public void setEditable(boolean editable) {
        getHttpPanelHexModel().setEditable(editable);
        if (!editable) {
            getHttpPanelHexModel().setData(new byte[0]);
        }
    }

    @Override
    public void dataChanged(HttpPanelViewModelEvent e) {
        getHttpPanelHexModel().setData(model.getData());
    }

    @Override
    public void save() {
        model.setData(getHttpPanelHexModel().getData());
    }

    @Override
    public void setParentConfigurationKey(String configurationKey) {}

    @Override
    public void loadConfiguration(FileConfiguration fileConfiguration) {}

    @Override
    public void saveConfiguration(FileConfiguration fileConfiguration) {}

    @Override
    public void setSelected(boolean selected) {
        if (selected) {
            hexTableBody.requestFocusInWindow();
        }
    }

    @Override
    public HttpPanelViewModel getModel() {
        return model;
    }

    @Override
    public void viewStateUpdated(ViewState vs) {
        if (vs != null) {
            String info = "";
            logger.debug("ViewState updated: {} :: {}", vs.getType(), vs.getValue());
            if (vs.getType().equalsIgnoreCase(JSFViewState.KEY)) {
                if (vs.getDecodedValue() != null) {
                    info = Constant.messages.getString("viewstate.en.type") + ": " + vs.getType();
                } else {
                    // Check for stateless
                    if (vs.getValue().equalsIgnoreCase("stateless")) {
                        info =
                                Constant.messages.getString("viewstate.en.type")
                                        + ": "
                                        + vs.getType()
                                        + " "
                                        + Constant.messages.getString("viewstate.en.stateless");
                    } else {
                        info =
                                Constant.messages.getString("viewstate.en.type")
                                        + ": "
                                        + vs.getType()
                                        + " "
                                        + Constant.messages.getString("viewstate.en.noparse");
                    }
                }
            }
            if (vs.getType().equalsIgnoreCase(ASPViewState.KEY)) {
                ASPViewState aVs = (ASPViewState) vs;
                String ver;
                String hasMac;
                switch (aVs.getVersion()) {
                    case ASPNET1:
                        ver = "ASPv1";
                        break;
                    case ASPNET2:
                        ver = "ASPv2";
                        break;
                    case UNKNOWN:
                    default:
                        ver = "ASPv?";
                        break;
                }
                if (aVs.hasMACtest1() || aVs.hasMACtest2()) {
                    hasMac = Constant.messages.getString("viewstate.en.mac");
                } else {
                    hasMac = Constant.messages.getString("viewstate.en.nomac");
                }
                info =
                        Constant.messages.getString("viewstate.en.type")
                                + ": "
                                + ver
                                + " ["
                                + hasMac
                                + "]";
            }
            vsInfoTxt.setText(info);
        } else {
            vsInfoTxt.setText(Constant.messages.getString("viewstate.en.novstate"));
        }
    }
}
