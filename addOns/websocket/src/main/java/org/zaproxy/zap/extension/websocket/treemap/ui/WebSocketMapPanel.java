package org.zaproxy.zap.extension.websocket.treemap.ui;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.model.Model;
import org.zaproxy.zap.extension.websocket.ExtensionWebSocket;
import org.zaproxy.zap.extension.websocket.WebSocketMessage;
import org.zaproxy.zap.extension.websocket.WebSocketObserver;
import org.zaproxy.zap.extension.websocket.WebSocketProxy;
import org.zaproxy.zap.extension.websocket.treemap.nodes.WebSocketTreeNode;
import org.zaproxy.zap.extension.websocket.ui.WebSocketPanel;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.LayoutHelper;

import javax.swing.*;
import javax.swing.event.TreeSelectionEvent;
import javax.swing.event.TreeSelectionListener;
import javax.swing.tree.*;
import java.awt.*;

public class WebSocketMapPanel extends AbstractPanel implements WebSocketObserver {
	private static final long serialVersionUID =  00000001000010001L;
	
	public static final int WEBSOCKET_OBSERVING_ORDER = WebSocketPanel.WEBSOCKET_OBSERVING_ORDER + 1;
	
	public static final ImageIcon disconnectIcon;
	public static final ImageIcon connectIcon;
	
	public static final ImageIcon disconnectTargetIcon;
	public static final ImageIcon connectTargetIcon;
	
	private JToolBar panelToolbar = null;
	
	private JButton addNewConnectionButton = null;
	private JTree treeMap = null;
	
	private ScannerUIHelper scannerUIHelper;
	
	static {
		disconnectIcon = new ImageIcon(WebSocketMapPanel.class.getResource("/resource/icon/fugue/plug-disconnect.png"));
		connectIcon = new ImageIcon(WebSocketMapPanel.class.getResource("/resource/icon/fugue/plug-connect.png"));
		
		disconnectTargetIcon = new ImageIcon(WebSocketMapPanel.class.getResource("/resource/icon/fugue/plug-disconnect-target.png"));
		connectTargetIcon = new ImageIcon(WebSocketMapPanel.class.getResource("/resource/icon/fugue/plug-connect-target.png"));
	};
	
	
	private static final Logger LOGGER = Logger.getLogger(WebSocketMapPanel.class);
	
	private ExtensionWebSocket extensionWebSocket;
	
	private WebSocketMapUI webSocketMapUI;
	
	/**
	 * Constructor which initialize the Panel
	 */
	public WebSocketMapPanel(ExtensionWebSocket extensionWebSocket, WebSocketMapUI webSocketMapUI){
		super();
		this.extensionWebSocket = extensionWebSocket;
		this.webSocketMapUI = webSocketMapUI;
		initialize();
		scannerUIHelper = new ScannerUIHelper();
	}
	
	private void initialize(){
		this.setHideable(true);
		this.setIcon(disconnectIcon);
		this.setName(Constant.messages.getString("websocket.treemap.title"));
//		this.setDefaultAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_S, Toolkit.getDefaultToolkit().getMenuShortcutKeyMask() | KeyEvent.SHIFT_DOWN_MASK, false));
		
		if (Model.getSingleton().getOptionsParam().getViewParam().getWmUiHandlingOption() == 0) {
			this.setSize(300,200);
		}
		
		this.setLayout(new GridBagLayout());
		this.add(getPanelToolbar(), LayoutHelper.getGBC(0, 0, 1, 0, new Insets(2,2,2,2)));
		this.add(new WebSocketTreePanel(getTreeSite(), "sitesPanelScrollPane"), LayoutHelper.getGBC(0, 1, 1, 1.0, 1.0, GridBagConstraints.BOTH, new Insets(2,2,2,2)));
		
		expandRoot();
		
	}
	
	private javax.swing.JToolBar getPanelToolbar() {
		if (panelToolbar == null) {
			
			panelToolbar = new javax.swing.JToolBar();
			panelToolbar.setLayout(new GridBagLayout());
			panelToolbar.setEnabled(true);
			panelToolbar.setFloatable(false);
			panelToolbar.setRollover(true);
			panelToolbar.setPreferredSize(new Dimension(800,30));
			panelToolbar.setName("WebSocket Toolbar");
			
			int i = 1;
			panelToolbar.add(getAddNewConnectionButton(), LayoutHelper.getGBC(i++, 0, 1, 0.0D));
			
		}
		return panelToolbar;
	}
	
	private JButton getAddNewConnectionButton(){
		if(addNewConnectionButton == null){
			addNewConnectionButton = new JButton();
			//TODO: Check Those References
			addNewConnectionButton.setIcon(DisplayUtils.getScaledIcon(new ImageIcon(WebSocketMapPanel.class.getResource("/org/zaproxy/zap/extension/websocket/resources/icons/plug--plus.png"))));
			addNewConnectionButton.setToolTipText(Constant.messages.getString("websocket.treemap.button.add_new_connection"));
			//TODO: Add Listener
		}
		return addNewConnectionButton;
		
	}
	
	/**
	 * This method initializes treeSite
	 *
	 * @return javax.swing.JTree
	 */
	public JTree getTreeSite() {
		if (treeMap == null) {
			
			treeMap = new JTree(webSocketMapUI);
			treeMap.setShowsRootHandles(true);
			treeMap.getSelectionModel().setSelectionMode(TreeSelectionModel.SINGLE_TREE_SELECTION);
			treeMap.setName("treeSite");
			treeMap.setToggleClickCount(1);
			
			// Force macOS L&F to query the row height from SiteMapTreeCellRenderer to hide the filtered nodes.
			// Other L&Fs hide the filtered nodes by default.
			LookAndFeel laf = UIManager.getLookAndFeel();
			if (laf != null && Constant.isMacOsX()
					&& UIManager.getSystemLookAndFeelClassName().equals(laf.getClass().getName())) {
				treeMap.setRowHeight(0);
			}
			
			treeMap.addTreeSelectionListener(new TreeSelectionListener() {
				
				@Override
				public void valueChanged(TreeSelectionEvent e) {

//                    WebSocketTreeNode node = (WebSocketTreeNode) treeMap.getLastSelectedPathComponent();
//                    if (node == null) {
//                        return;
//                    }
//                    if (!node.isRoot()) {
//                        HttpMessage msg = null;
//                        try {
//                            msg = node.getHistoryReference().getHttpMessage();
//                        } catch (Exception e1) {
//                            // ZAP: Log exceptions
//                            log.warn(e1.getMessage(), e1);
//                            return;
//
//                        }
//
//                        getView().displayMessage(msg);
//
//                        // ZAP: Call SiteMapListenners
//                        for (SiteMapListener listener : listeners) {
//                            listener.nodeSelected(node);
//                        }
//                    } else {
//                        // ZAP: clear the views when the root is selected
//                        getView().displayMessage(null);
//                    }
//
				}
			});
//            treeMap.setComponentPopupMenu(new SitesCustomPopupMenu());
			
			// ZAP: Add custom tree cell renderer.
			DefaultTreeCellRenderer renderer = new WebSocketMapTreeCellRender();
			treeMap.setCellRenderer(renderer);
			treeMap.setComponentPopupMenu(new ContextsCustomPopupMenu());
			String deleteSiteNode = "zap.delete.sitenode";
//            treeMap.getInputMap().put(getView().getDefaultDeleteKeyStroke(), deleteSiteNode);
//            treeMap.getActionMap().put(deleteSiteNode, new AbstractAction() {
//
//                private static final long serialVersionUID = 1L;
//
//                @Override
//                public void actionPerformed(ActionEvent e) {
//                    ExtensionHistory extHistory = Control.getSingleton().getExtensionLoader().getExtension(
//                            ExtensionHistory.class);
//                    if (extHistory == null || treeMap.getSelectionCount() == 0) {
//                        return;
//                    }
//
//                    int result = View.getSingleton().showConfirmDialog(Constant.messages.getString("sites.purge.warning"));
//                    if (result != JOptionPane.YES_OPTION) {
//                        return;
//                    }
//
//                    SiteMap siteMap = Model.getSingleton().getSession().getSiteTree();
//                    for (TreePath path : treeMap.getSelectionPaths()) {
//                        extHistory.purge(siteMap, (SiteNode) path.getLastPathComponent());
//                    }
//                }
//            });
		}
		return treeMap;
	}
	
	public void expandRoot() {
		TreeNode root = (TreeNode) treeMap.getModel().getRoot();
		if (root == null) {
			return;
		}
		final TreePath rootTreePath = new TreePath(root);
		
		if (EventQueue.isDispatchThread()) {
			getTreeSite().expandPath(rootTreePath);
			return;
		}
		try {
			EventQueue.invokeLater(() -> getTreeSite().expandPath(rootTreePath));
		} catch (Exception e) {
			// ZAP: Log exceptions
			LOGGER.warn(e.getMessage(), e);
		}
	}
	
	@Override
	public int getObservingOrder() {
		return WEBSOCKET_OBSERVING_ORDER;
	}
	
	@Override
	public boolean onMessageFrame(int channelId, WebSocketMessage message) {
		return false;
	}
	
	@Override
	public void onStateChange(WebSocketProxy.State state, WebSocketProxy proxy) {
	
	}
	
	protected class ContextsCustomPopupMenu extends JPopupMenu {

		private static final long serialVersionUID = 1L;
		
		private MainWebSocketPopupMenu popupMenu = null;
		
		private WebSocketNodeUI latestNode = null;
		
		private MainWebSocketPopupMenu getPopupMenu() {
			if(popupMenu == null){
				JMenuItem activeScan = scannerUIHelper.getActiveScanMenuItem();
				
				activeScan.addActionListener(actionEvent -> {
					LOGGER.warn("Action Event: " + actionEvent.getActionCommand());
					if(latestNode != null){
						if(extensionWebSocket.getWebSocketActiveScanManager().startScan((WebSocketTreeNode) latestNode.getWebSocketNode(),true) == -1){
							JOptionPane.showMessageDialog(this,
									"Another Scan Running...");
						};
					}
				});
				
				scannerUIHelper.addToMenu(activeScan);
				popupMenu = scannerUIHelper.getWebSocketPopupMenu();
			}
			
			return popupMenu;
		}
		
		
		@Override
		public void show(Component invoker, int x, int y) {
			// Select context list item on right click
			latestNode = (WebSocketNodeUI) treeMap.getLastSelectedPathComponent();
			TreePath tp = treeMap.getPathForLocation(x, y);
			if ( tp != null ) {
				boolean select = true;
				// Only select a new item if the current item is not
				// already selected - this is to allow multiple items
				// to be selected
				if (treeMap.getSelectionPaths() != null) {
					for (TreePath t : treeMap.getSelectionPaths()) {
						if (t.equals(tp)) {
							select = false;
							break;
						}
					}
				}
				if (select) {
					treeMap.getSelectionModel().setSelectionPath(tp);
				}
			}
			getPopupMenu().show(treeMap, x, y);
		}
		
	}
}
