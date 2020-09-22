/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2013 The ZAP Development Team
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
package org.zaproxy.zap.extension.sse.ui;

import java.awt.Component;
import java.awt.Dimension;
import java.awt.EventQueue;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.HashSet;
import java.util.Set;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JToggleButton;
import javax.swing.JToolBar;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.control.Control.Mode;
import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.extension.SessionChangedListener;
import org.parosproxy.paros.extension.history.LogPanel;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.httppanel.HttpPanel;
import org.zaproxy.zap.extension.sse.EventStreamException;
import org.zaproxy.zap.extension.sse.EventStreamObserver;
import org.zaproxy.zap.extension.sse.EventStreamProxy.State;
import org.zaproxy.zap.extension.sse.ExtensionServerSentEvents;
import org.zaproxy.zap.extension.sse.ServerSentEvent;
import org.zaproxy.zap.extension.sse.db.EventStreamStorage;
import org.zaproxy.zap.extension.sse.db.ServerSentEventStream;
import org.zaproxy.zap.extension.sse.db.TableEventStream;
import org.zaproxy.zap.extension.sse.ui.filter.EventStreamViewFilter;
import org.zaproxy.zap.extension.sse.ui.filter.EventStreamViewFilterDialog;
import org.zaproxy.zap.utils.StickyScrollbarAdjustmentListener;
import org.zaproxy.zap.view.ZapToggleButton;

/**
 * Represents the Server-Sent Events tab. It listens to all Event Streams and displays events
 * accordingly.
 */
public class EventStreamPanel extends AbstractPanel implements EventStreamObserver {

    private static final long serialVersionUID = -4518225363808518571L;

    private static final Logger logger = Logger.getLogger(EventStreamPanel.class);

    /** Observe messages after storage handler was called. */
    public static final int EVENT_STREAM_OBSERVING_ORDER =
            EventStreamStorage.EVENT_STREAM_OBSERVING_ORDER + 5;

    /** Depending on its count, the tab uses either a connected or disconnected icon. */
    static Set<Integer> connectedStreamIds;

    public static final ImageIcon icon;

    static {
        connectedStreamIds = new HashSet<>();

        icon =
                new ImageIcon(
                        ExtensionServerSentEvents.class.getResource(
                                "resources/download-cloud.png"));
    }

    private JToolBar panelToolbar = null;

    private ZapToggleButton scopeButton;

    //	private JComboBox<SSE> channelSelect;
    //	private ChannelSortedListModel channelsModel;
    //	private ComboBoxChannelModel channelSelectModel;

    private JButton handshakeButton;
    private JButton brkButton;
    private JButton filterButton;

    private JLabel filterStatus;
    private EventStreamViewFilterDialog filterDialog;

    private JButton optionsButton;

    private JScrollPane scrollPanel;
    private EventStreamView eventsView;
    private EventStreamViewModel eventsModel;

    //	private WebSocketBreakpointsUiManagerInterface brkManager;

    private TableEventStream table;

    private HttpPanel requestPanel;
    private HttpPanel responsePanel;

    private SessionListener sessionListener;

    /**
     * Panel is added as tab beside the History tab.
     *
     * @param table
     * @param brkManager
     */
    public EventStreamPanel(
            TableEventStream table) { // , WebSocketBreakpointsUiManagerInterface brkManager) {
        super();

        //		this.brkManager = brkManager;
        //		brkManager.setWebSocketPanel(this);

        this.table = table;
        //		channelsModel = new ChannelSortedListModel();
        //		channelSelectModel = new ComboBoxChannelModel(channelsModel);

        eventsModel = new EventStreamViewModel(this.table, getFilterDialog().getFilter());
        eventsView = new EventStreamView(eventsModel);

        initializePanel();
    }

    public void setDisplayPanel(HttpPanel requestPanel, HttpPanel responsePanel) {
        this.requestPanel = requestPanel;
        this.responsePanel = responsePanel;

        eventsView.setDisplayPanel(requestPanel, responsePanel);
    }

    /** Sets up the graphical representation of this tab. */
    private void initializePanel() {
        setName(Constant.messages.getString("sse.panel.title"));
        setLayout(new GridBagLayout());

        GridBagConstraints constraints = new GridBagConstraints();
        constraints.anchor = GridBagConstraints.NORTHWEST;
        constraints.fill = GridBagConstraints.HORIZONTAL;
        constraints.insets = new Insets(2, 2, 2, 2);
        constraints.weightx = 1.0;
        add(getPanelToolbar(), constraints);

        constraints = new GridBagConstraints();
        constraints.anchor = java.awt.GridBagConstraints.NORTHWEST;
        constraints.fill = java.awt.GridBagConstraints.BOTH;
        constraints.gridy = 1;
        constraints.weightx = 1.0;
        constraints.weighty = 1.0;
        add(getWorkPanel(), constraints);

        setIcon(EventStreamPanel.icon);
    }

    /**
     * Lazy initializes header of this SSE tab with a select box and a filter.
     *
     * @return
     */
    private Component getPanelToolbar() {
        if (panelToolbar == null) {
            panelToolbar = new JToolBar();
            panelToolbar.setLayout(new GridBagLayout());
            panelToolbar.setEnabled(true);
            panelToolbar.setFloatable(false);
            panelToolbar.setRollover(true);
            panelToolbar.setPreferredSize(new java.awt.Dimension(800, 30));
            panelToolbar.setFont(new java.awt.Font("Dialog", java.awt.Font.PLAIN, 12));
            panelToolbar.setName("eventstream.toolbar");

            //			GridBagConstraints constraints;
            //			int x = 0;
            //
            //			constraints = new GridBagConstraints();
            //			constraints.gridx = x++;
            //			panelToolbar.add(getScopeButton());
            //
            //			constraints = new GridBagConstraints();
            //			constraints.gridx = x++;
            //			panelToolbar.add(new
            // JLabel(Constant.messages.getString("sse.toolbar.stream.label")), constraints);
            //
            ////			constraints = new GridBagConstraints();
            ////			constraints.gridx = x++;
            ////			panelToolbar.add(getChannelSelect(), constraints);
            //
            //			constraints = new GridBagConstraints();
            //			constraints.gridx = x++;
            //			panelToolbar.add(getShowHandshakeButton(), constraints);
            //
            ////			if (brkManager != null) {
            ////				// ExtensionBreak is not disabled
            ////				constraints = new GridBagConstraints();
            ////				constraints.gridx = x++;
            ////				panelToolbar.add(getAddBreakpointButton(), constraints);
            ////			}
            ////
            ////			panelToolbar.addSeparator();
            ////			x++;
            //
            //			constraints = new GridBagConstraints();
            //			constraints.gridx = x++;
            //			panelToolbar.add(getFilterButton(), constraints);
            //
            //			constraints = new GridBagConstraints();
            //			constraints.gridx = x++;
            //			panelToolbar.add(getFilterStatus(), constraints);
            //
            //			// stretch pseudo-component to let options button appear on the right
            //			constraints = new GridBagConstraints();
            //			constraints.gridx = x++;
            //			constraints.weightx = 1;
            //			constraints.fill = GridBagConstraints.HORIZONTAL;
            //			panelToolbar.add(new JLabel(), constraints);
            //
            //			constraints = new GridBagConstraints();
            //			constraints.gridx = x++;
            //			panelToolbar.add(getOptionsButton(), constraints);
        }

        return panelToolbar;
    }

    //	protected JComboBox<WebSocketChannelDTO> getChannelSelect() {
    //		if (channelSelect == null) {
    //			channelSelect = new JComboBox<>(channelSelectModel);
    //			channelSelect.setRenderer(new ComboBoxChannelRenderer());
    //			channelSelect.setMaximumRowCount(8);
    //			channelSelect.addActionListener(new ActionListener() {
    //
    //				@Override
    //				public void actionPerformed(ActionEvent e) {
    //
    //				    WebSocketChannelDTO channel = (WebSocketChannelDTO) channelSelect.getSelectedItem();
    //				    if (channel != null && channel.id != null) {
    //				    	// has valid element selected + a valid reference
    //				        useModel(channel.id);
    //				    } else {
    //				        useJoinedModel();
    //				    }
    //
    //			        if (channel != null && channel.historyId != null) {
    //			        	getShowHandshakeButton().setEnabled(true);
    //			        } else {
    //				        getShowHandshakeButton().setEnabled(false);
    //			        }
    //
    //			        eventsView.revalidate();
    //				}
    //			});
    //		}
    //		return channelSelect;
    //	}

    private JButton getOptionsButton() {
        if (optionsButton == null) {
            optionsButton = new JButton();
            optionsButton.setToolTipText(Constant.messages.getString("sse.toolbar.button.options"));
            optionsButton.setIcon(
                    new ImageIcon(EventStreamPanel.class.getResource("/resource/icon/16/041.png")));
            optionsButton.addActionListener(
                    new ActionListener() {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            Control.getSingleton()
                                    .getMenuToolsControl()
                                    .options(Constant.messages.getString("sse.panel.title"));
                        }
                    });
        }
        return optionsButton;
    }

    private Component getFilterButton() {
        if (filterButton == null) {
            filterButton = new JButton();
            filterButton.setIcon(
                    new ImageIcon(
                            EventStreamPanel.class.getResource(
                                    "/resource/icon/16/054.png"))); // 'filter' icon
            filterButton.setToolTipText(Constant.messages.getString("sse.filter.button.filter"));

            final EventStreamPanel panel = this;
            filterButton.addActionListener(
                    new ActionListener() {

                        @Override
                        public void actionPerformed(ActionEvent e) {
                            panel.showFilterDialog();
                        }
                    });
        }
        return filterButton;
    }

    private JLabel getFilterStatus() {
        if (filterStatus == null) {
            String base = Constant.messages.getString("sse.filter.label.filter");
            String status = Constant.messages.getString("sse.filter.label.off");
            filterStatus = new JLabel(base + status);
        }
        return filterStatus;
    }

    private Component getShowHandshakeButton() {
        if (handshakeButton == null) {
            handshakeButton = new JButton();
            handshakeButton.setEnabled(false);
            handshakeButton.setIcon(
                    new ImageIcon(
                            EventStreamPanel.class.getResource("/resource/icon/16/handshake.png")));
            handshakeButton.setToolTipText(
                    Constant.messages.getString("sse.filter.button.handshake"));

            //			final JComboBox<WebSocketChannelDTO> channelSelect = this.channelSelect;
            //			handshakeButton.addActionListener(new ActionListener() {
            //
            //				@Override
            //				public void actionPerformed(ActionEvent evt) {
            //					WebSocketChannelDTO channel = (WebSocketChannelDTO)
            // channelSelect.getSelectedItem();
            //					HistoryReference handshakeRef = channel.getHandshakeReference();
            //					if (handshakeRef != null) {
            //						HttpMessage msg;
            //						try {
            //                            msg = handshakeRef.getHttpMessage();
            //                        } catch (Exception e) {
            //                        	logger.warn(e.getMessage(), e);
            //                            return;
            //                        }
            //						showHandshakeMessage(msg);
            //					}
            //				}
            //			});
        }
        return handshakeButton;
    }

    private void showHandshakeMessage(HttpMessage msg) {
        if (msg.getRequestHeader().isEmpty()) {
            requestPanel.clearView(true);
        } else {
            requestPanel.setMessage(msg);
        }

        if (msg.getResponseHeader().isEmpty()) {
            responsePanel.clearView(false);
        } else {
            responsePanel.setMessage(msg, true);
        }

        requestPanel.setTabFocus();
    }

    private Component getAddBreakpointButton() {
        if (brkButton == null) {
            brkButton = new JButton();
            brkButton.setIcon(
                    new ImageIcon(
                            EventStreamPanel.class.getResource("/resource/icon/16/break_add.png")));
            brkButton.setToolTipText(Constant.messages.getString("sse.filter.button.break_add"));

            //			final WebSocketBreakpointsUiManagerInterface brkManager = this.brkManager;
            //			brkButton.addActionListener(new ActionListener() {
            //
            //				@Override
            //				public void actionPerformed(ActionEvent e) {
            //					brkManager.handleAddBreakpoint(new WebSocketMessageDTO());
            //				}
            //			});
        }
        return brkButton;
    }

    /**
     * Lazy initializes the part of the SSE tab that is used to display the events.
     *
     * @return
     */
    private JComponent getWorkPanel() {
        if (scrollPanel == null) {
            // alternatively you can use:
            // scrollPanel = LazyViewport.createLazyScrollPaneFor(getMessagesLog());
            // updates viewport only when scrollbar is released

            scrollPanel = new JScrollPane(eventsView.getViewComponent());
            scrollPanel.setPreferredSize(new Dimension(800, 200));
            scrollPanel.setName("EventStreamPanelActions");

            scrollPanel
                    .getVerticalScrollBar()
                    .addAdjustmentListener(new StickyScrollbarAdjustmentListener());
        }
        return scrollPanel;
    }

    /**
     * Updates icon of this tab.
     *
     * @param icon
     */
    private synchronized void updateIcon(ImageIcon icon) {
        setIcon(icon);

        // workaround to update icon of tab
        Component c = getParent();
        if (c instanceof JTabbedPane) {
            JTabbedPane tab = (JTabbedPane) c;
            int index = tab.indexOfComponent(this);
            tab.setIconAt(index, icon);
        }
    }

    @Override
    public boolean onServerSentEvent(ServerSentEvent event) {
        eventsModel.fireMessageArrived(event);
        return true;
    }

    @Override
    public int getServerSentEventObservingOrder() {
        return EVENT_STREAM_OBSERVING_ORDER;
    }

    @Override
    public void onServerSentEventStateChange(
            final State state, final ServerSentEventStream stream) {

        try {
            if (EventQueue.isDispatchThread()) {
                updateStreamState(state, stream);
            } else {
                EventQueue.invokeAndWait(
                        new Runnable() {
                            @Override
                            public void run() {
                                updateStreamState(state, stream);
                            }
                        });
            }
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
        }
    }

    private void updateStreamState(State state, ServerSentEventStream stream) {
        int connectedStreamCount = 0;
        boolean isNewChannel = false;

        synchronized (connectedStreamIds) {
            boolean isConnectedChannel = connectedStreamIds.contains(stream.getId());

            switch (state) {
                case CLOSED:
                    if (isConnectedChannel && stream.getEndTimestamp() != null) {
                        connectedStreamIds.remove(stream.getId());

                        // updates icon
                        //					channelsModel.updateElement(stream);
                    }
                    break;

                case EXCLUDED:
                    // remove from UI
                    connectedStreamIds.remove(stream.getId());
                    //				channelsModel.removeElement(stream);

                    eventsModel.fireTableDataChanged();
                    break;

                case OPEN:
                    if (!isConnectedChannel && stream.getEndTimestamp() == null) {
                        connectedStreamIds.add(stream.getId());
                        //					channelsModel.addElement(stream);
                        isNewChannel = true;
                    }
                    break;

                case INCLUDED:
                    // add to UI (probably again)
                    connectedStreamIds.add(stream.getId());
                    //				channelsModel.addElement(stream);

                    eventsModel.fireTableDataChanged();
                    isNewChannel = true;
                    break;

                default:
            }

            // change appearance of WebSocket tab header
            connectedStreamCount = connectedStreamIds.size();
        }
    }

    /**
     * Set current displayed channel.
     *
     * @param channelId
     */
    private void useModel(int channelId) {
        eventsModel.setActiveStream(channelId);
    }

    /** Get model that contains all messages from all channels. */
    private void useJoinedModel() {
        eventsModel.setActiveStream(null);
    }

    /**
     * Lazy initializes the filter dialog.
     *
     * @return filter dialog
     */
    public EventStreamViewFilterDialog getFilterDialog() {
        if (filterDialog == null) {
            filterDialog =
                    new EventStreamViewFilterDialog(View.getSingleton().getMainFrame(), true);
        }
        return filterDialog;
    }

    /**
     * Shows filter dialog
     *
     * @return 1 is returned if applied, -1 when dialog was reseted.
     */
    protected int showFilterDialog() {
        EventStreamViewFilterDialog dialog = getFilterDialog();
        dialog.setModal(true);

        int exit = dialog.showDialog();

        int result = 0;
        switch (exit) {
            case JOptionPane.OK_OPTION:
                // some changes were applied
                result = 1;
                break;

            case JOptionPane.NO_OPTION:
                // reset button was pressed
                result = -1;
                break;

            case JOptionPane.CANCEL_OPTION:
                // nothing has changed - do not filter again
                return result;
        }

        setFilterStatus();
        applyFilter();

        return result;
    }

    /** Apply filter to visible parts of models. */
    private void applyFilter() {
        eventsModel.fireFilterChanged();
    }

    /**
     * Show textual hint for filter status.
     *
     * @param filter
     */
    private void setFilterStatus() {
        EventStreamViewFilter filter = getFilterDialog().getFilter();
        JLabel status = getFilterStatus();

        status.setText(filter.toLongString());
        status.setToolTipText(filter.toLongString());
    }

    //    /**
    //	 * Exposes the channels list model. The model must not be modified.
    //	 *
    //	 * @return a {@code ChannelSortedListModel} with all channels available
    //	 */
    //    public ChannelSortedListModel getChannelsModel() {
    //		return channelsModel;
    //	}

    /** Updates the messages view and the combo box that is used to filter channels. */
    public void update() {
        // reset table contents
        eventsModel.fireTableDataChanged();

        //		synchronized (channelsModel) {
        //			// reset channel selector's model
        //			Object selectedItem = channelSelectModel.getSelectedItem();
        //
        //			channelsModel.reset();
        //
        //			try {
        //				for (WebSocketChannelDTO channel : table.getChannelItems()) {
        //					channelsModel.addElement(channel);
        //				}
        //
        //				int index = channelSelectModel.getIndexOf(selectedItem);
        //				if (index == -1) {
        //					index = 0;
        //				}
        //				channelSelect.setSelectedIndex(index);
        //			} catch (SQLException e) {
        //				logger.error(e.getMessage(), e);
        //			}
        //		}
    }

    public void showEvent(ServerSentEvent event) throws EventStreamException {
        setTabFocus();

        // show channel if not already active
        Integer activeChannelId = eventsModel.getActiveStreamId();
        if (event.getStreamId() != null && !event.getStreamId().equals(activeChannelId)) {
            eventsModel.setActiveStream(event.getStreamId());
            //			channelSelectModel.setSelectedChannelId(event.getStreamId());
        }

        // check if message is filtered out
        EventStreamViewFilter filter = getFilterDialog().getFilter();
        if (filter.isDenylisted(event)) {
            // make it visible by resetting filter
            filter.reset();
            setFilterStatus();
            applyFilter();
        }

        // select message and scroll there
        eventsView.selectAndShowItem(event);
    }

    public SessionListener getSessionListener() {
        if (sessionListener == null) {
            sessionListener = new SessionListener();
        }
        return sessionListener;
    }

    private class SessionListener implements SessionChangedListener {

        @Override
        public void sessionAboutToChange(Session session) {
            // new messages that arrive are buffered in TableWebSocket
            // but existing messages shouldn't be read while the old database is
            // closed and another database is opened => stop UI from accessing DB

            if (EventQueue.isDispatchThread()) {
                pause();
                reset();
            } else {
                try {
                    EventQueue.invokeAndWait(
                            new Runnable() {
                                @Override
                                public void run() {
                                    pause();
                                    reset();
                                }
                            });
                } catch (Exception e) {
                    logger.error(e.getMessage(), e);
                }
            }
        }

        @Override
        public void sessionChanged(Session session) {
            resume();
        }

        @Override
        public void sessionModeChanged(Mode mode) {}

        @Override
        public void sessionScopeChanged(Session session) {}
    }

    /** Clear control elements, set back to default. */
    public void reset() {
        // select '-- All Channels --' item
        //		if (channelSelect.getSelectedIndex() != 0) {
        //			channelSelect.setSelectedIndex(0);
        //		}

        // reset filter
        getFilterDialog().getFilter().reset();
    }

    /**
     * Disables all components that access the database. Call it when another database is in load.
     */
    public void pause() {
        eventsView.pause();
        //		channelSelect.setEnabled(false);
    }

    /**
     * Enables all components that access the database. Call it when no other database is in load.
     */
    public void resume() {
        eventsView.resume();
        //		channelSelect.setEnabled(true);
        update();
    }

    private JToggleButton getScopeButton() {
        if (scopeButton == null) {
            scopeButton = new ZapToggleButton();
            scopeButton.setIcon(
                    new ImageIcon(
                            LogPanel.class.getResource("/resource/icon/fugue/target-grey.png")));
            scopeButton.setSelectedIcon(
                    new ImageIcon(
                            EventStreamPanel.class.getResource("/resource/icon/fugue/target.png")));
            scopeButton.setToolTipText(
                    Constant.messages.getString("history.scope.button.unselected"));
            scopeButton.setSelectedToolTipText(
                    Constant.messages.getString("history.scope.button.selected"));

            scopeButton.addActionListener(
                    new java.awt.event.ActionListener() {

                        @Override
                        public void actionPerformed(java.awt.event.ActionEvent e) {
                            // show channels only in scope in JComboBox (select element)
                            boolean isShowJustInScope = scopeButton.isSelected();

                            //					channelsModel.setShowJustInScope(isShowJustInScope);
                            //					if (!channelsModel.contains(channelSelect.getSelectedItem())) {
                            //						// select first entry, if selected item does no longer appear in
                            // drop-down
                            //						channelSelect.setSelectedIndex(0);
                            //					}

                            // show messages only from channels in scope
                            getFilterDialog().getFilter().setShowJustInScope(isShowJustInScope);
                            applyFilter();
                        }
                    });
        }
        return scopeButton;
    }

    public void setTable(TableEventStream table) {
        this.table = table;
        this.eventsModel.setTable(table);
    }
}
