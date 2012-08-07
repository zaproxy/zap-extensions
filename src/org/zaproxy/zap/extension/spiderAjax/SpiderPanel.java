/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); 
 * you may not use this file except in compliance with the License. 
 * You may obtain a copy of the License at 
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0 
 *   
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS, 
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
 * See the License for the specific language governing permissions and 
 * limitations under the License. 
 */
package org.zaproxy.zap.extension.spiderAjax;

import java.awt.BorderLayout;
import java.awt.EventQueue;
import java.awt.GridBagConstraints;
import java.awt.Rectangle;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.InputEvent;
import java.util.Enumeration;
import java.util.Vector;
import javax.swing.*;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.common.AbstractParam;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.extension.history.HistoryFilter;
import org.parosproxy.paros.extension.history.LogPanel;
import org.parosproxy.paros.extension.history.LogPanelCellRenderer;
import org.parosproxy.paros.model.HistoryList;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.bruteforce.BruteForcePanel;
import org.zaproxy.zap.extension.fuzz.FuzzerPanel;
import org.zaproxy.zap.extension.httppanel.HttpPanel;
import org.zaproxy.zap.extension.spiderAjax.SpiderPanel;
import org.zaproxy.zap.extension.spiderAjax.SpiderThread;


public class SpiderPanel extends AbstractPanel implements Runnable {
	private static final long serialVersionUID = 1L;
	private static final Logger logger = Logger.getLogger(LogPanel.class);
	private javax.swing.JScrollPane scrollLog = null;
	private javax.swing.JList listLog = null;
	private javax.swing.JPanel historyPanel = null;
	private javax.swing.JToolBar panelToolbar = null;
	private JLabel filterStatus = null;
	private HttpPanel requestPanel = null;
	private HttpPanel responsePanel = null;
    private ExtensionAjax extension = null;
	private SpiderThread runnable = null;
	private HistoryList list = null;
	private JButton stopScanButton;
	private JButton startScanButton;
	private JButton optionsButton = null;


	/**
	 * This is the default constructor
	 */
	public SpiderPanel(ExtensionAjax e) {
		super();
		this.extension = e;
		initialize();
	}
	
	/**
	 * This method initializes this
	 * 
	 * @return void
	 */
	private  void initialize() {
		this.setLayout(new BorderLayout());
	    if (Model.getSingleton().getOptionsParam().getViewParam().getWmUiHandlingOption() == 0) {
	    	this.setSize(600, 200);
	    }
		this.add(getHistoryPanel(), java.awt.BorderLayout.CENTER);
		this.list = new HistoryList();
	}
    
    
	/**
	 * This method initializes scrollLog	
	 * 	
	 * @return javax.swing.JScrollPane	
	 */    
	private javax.swing.JScrollPane getScrollLog() {
		if (scrollLog == null) {
			scrollLog = new javax.swing.JScrollPane();
			scrollLog.setViewportView(getListLog());
			scrollLog.setHorizontalScrollBarPolicy(javax.swing.JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
			scrollLog.setVerticalScrollBarPolicy(javax.swing.JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
			scrollLog.setPreferredSize(new java.awt.Dimension(800,200));
			scrollLog.setName("scrollLog");
		}
		return scrollLog;
	}

	private javax.swing.JPanel getHistoryPanel() {
		if (historyPanel == null) {
			
			historyPanel = new javax.swing.JPanel();
			historyPanel.setLayout(new java.awt.GridBagLayout());
			historyPanel.setName("Spider AJAX Panel");
			
			GridBagConstraints gridBagConstraints1 = new GridBagConstraints();
			GridBagConstraints gridBagConstraints2 = new GridBagConstraints();

			gridBagConstraints1.gridx = 0;
			gridBagConstraints1.gridy = 0;
			gridBagConstraints1.weightx = 1.0D;
			gridBagConstraints1.insets = new java.awt.Insets(2,2,2,2);
			gridBagConstraints1.fill = java.awt.GridBagConstraints.HORIZONTAL;
			gridBagConstraints1.anchor = java.awt.GridBagConstraints.NORTHWEST;
			
			gridBagConstraints2.gridx = 0;
			gridBagConstraints2.gridy = 1;
			gridBagConstraints2.weightx = 1.0;
			gridBagConstraints2.weighty = 1.0;
			gridBagConstraints2.insets = new java.awt.Insets(0,0,0,0);
			gridBagConstraints2.fill = java.awt.GridBagConstraints.BOTH;
			gridBagConstraints2.anchor = java.awt.GridBagConstraints.NORTHWEST;

			historyPanel.add(this.getPanelToolbar(), gridBagConstraints1);
			historyPanel.add(getScrollLog(), gridBagConstraints2);

		}
		return historyPanel;
	}

	private JButton getStopScanButton() {
		if (stopScanButton == null) {
			stopScanButton = new JButton();
			stopScanButton.setToolTipText(this.extension.getString("ajax.toolbar.button.stop"));
			stopScanButton.setIcon(new ImageIcon(BruteForcePanel.class.getResource("/resource/icon/16/142.png")));
			stopScanButton.setEnabled(false);
			stopScanButton.addActionListener(new ActionListener () {
				@Override
				public void actionPerformed(ActionEvent e) {
					stopScan();
				}
			});
		}
		return stopScanButton;
	}
	
	private void stopScan() {
		this.getStartScanButton().setEnabled(true);
		this.getStopScanButton().setEnabled(false);
		this.runnable.stopSpider();
	}
	private JButton getStartScanButton() {
		if (startScanButton == null) {
			startScanButton = new JButton();
			startScanButton.setToolTipText(Constant.messages.getString("bruteforce.toolbar.button.start"));
			startScanButton.setIcon(new ImageIcon(BruteForcePanel.class.getResource("/resource/icon/16/131.png")));
			startScanButton.setEnabled(false);
			startScanButton.addActionListener(new ActionListener () {

				@Override
				public void actionPerformed(ActionEvent e) {
					//TODO: iniciar aqui el thread
				}

			});

		}
		return startScanButton;
	}
	
	private void startScan(String directory) {
		this.getStartScanButton().setEnabled(false);
		this.getStopScanButton().setEnabled(true);
	}	
	public HistoryList getHistList(){
		return this.list;
	}
	
	public void addHistoryUrl(HistoryReference r, HttpMessage msg, String url){
			if(isNewUrl(r, msg) && msg.getRequestHeader().getURI().toString().contains(url)){
				this.getHistList().addElement(r);
			}
		}
	
	public boolean isNewUrl(HistoryReference r, HttpMessage msg){
		Enumeration<?> e = this.getHistList().elements();
		while (e.hasMoreElements()) {
			if (e.nextElement().toString().contains(msg.getRequestHeader().getURI().toString())) {
				return false;
			}
		}
		return true;
	}
	
	private JButton getOptionsButton() {
		if (optionsButton == null) {
			optionsButton = new JButton();
			optionsButton.setToolTipText(this.extension.getString("ajax.toolbar.button.options"));
			optionsButton.setIcon(new ImageIcon(FuzzerPanel.class.getResource("/resource/icon/16/041.png")));
			optionsButton.addActionListener(new ActionListener () {
				@Override
				public void actionPerformed(ActionEvent e) {
					Control.getSingleton().getMenuToolsControl().options(
							extension.getString("ajax.proxy.local.title"));
				}
			});
		}
		return optionsButton;
	}
	private javax.swing.JToolBar getPanelToolbar() {
		if (panelToolbar == null) {
			
			panelToolbar = new javax.swing.JToolBar();
			panelToolbar.setLayout(new java.awt.GridBagLayout());
			panelToolbar.setEnabled(true);
			panelToolbar.setFloatable(false);
			panelToolbar.setRollover(true);
			panelToolbar.setPreferredSize(new java.awt.Dimension(800,30));
			panelToolbar.setFont(new java.awt.Font("Dialog", java.awt.Font.PLAIN, 12));
			panelToolbar.setName("Spider AJAX Toolbar");
			
			GridBagConstraints gridBagConstraints1 = new GridBagConstraints();
			GridBagConstraints gridBagConstraints2 = new GridBagConstraints();
			GridBagConstraints gridBagConstraints3 = new GridBagConstraints();
			GridBagConstraints gridBagConstraints4 = new GridBagConstraints();
			GridBagConstraints gridBagConstraints5 = new GridBagConstraints();
			GridBagConstraints gridBagConstraintsX = new GridBagConstraints();
			GridBagConstraints gridBagConstraints7 = new GridBagConstraints();
			GridBagConstraints gridBagConstraintsy = new GridBagConstraints();

			gridBagConstraints1.gridx = 0;
			gridBagConstraints1.gridy = 0;
			gridBagConstraints1.insets = new java.awt.Insets(0,0,0,0);
			gridBagConstraints1.anchor = java.awt.GridBagConstraints.WEST;
			
			// TODO this shouldnt push the filter button off the lhs
			gridBagConstraints2.gridx = 1;
			gridBagConstraints2.gridy = 0;
			gridBagConstraints2.insets = new java.awt.Insets(0,0,0,0);
			gridBagConstraints2.anchor = java.awt.GridBagConstraints.WEST;

			gridBagConstraints3.gridx = 2;
			gridBagConstraints3.gridy = 0;
			gridBagConstraints3.insets = new java.awt.Insets(0,0,0,0);
			gridBagConstraints3.anchor = java.awt.GridBagConstraints.WEST;

			gridBagConstraints4.gridx = 3;
			gridBagConstraints4.gridy = 0;
			gridBagConstraints4.insets = new java.awt.Insets(0,0,0,0);
			gridBagConstraints4.anchor = java.awt.GridBagConstraints.WEST;

			gridBagConstraints5.gridx = 4;
			gridBagConstraints5.gridy = 0;
			gridBagConstraints5.insets = new java.awt.Insets(0,0,0,0);
			gridBagConstraints5.anchor = java.awt.GridBagConstraints.WEST;
			gridBagConstraints7.gridx = 6;
			gridBagConstraints7.gridy = 0;
			gridBagConstraints7.insets = new java.awt.Insets(0,0,0,0);
			gridBagConstraints7.anchor = java.awt.GridBagConstraints.WEST;
			gridBagConstraintsX.gridx = 5;
			gridBagConstraintsX.gridy = 0;
			gridBagConstraintsX.weightx = 1.0;
			gridBagConstraintsX.weighty = 1.0;
			gridBagConstraintsX.insets = new java.awt.Insets(0,0,0,0);
			gridBagConstraintsX.anchor = java.awt.GridBagConstraints.EAST;
			gridBagConstraintsX.fill = java.awt.GridBagConstraints.HORIZONTAL;
			gridBagConstraintsy.gridx = 21;
			gridBagConstraintsy.gridy = 0;
			gridBagConstraintsy.insets = new java.awt.Insets(0,0,0,0);
			gridBagConstraintsy.anchor = java.awt.GridBagConstraints.WEST;
			filterStatus = new JLabel(this.extension.getString("ajax.panel.subtitle"));
			JLabel t1 = new JLabel();

			//panelToolbar.add(getFilterButton(), gridBagConstraints1);
			panelToolbar.add(filterStatus, gridBagConstraints2);
			panelToolbar.add(getStopScanButton(), gridBagConstraints1);
			//panelToolbar.add(getStartScanButton(), gridBagConstraints3);
			panelToolbar.add(getOptionsButton(), gridBagConstraintsy);

			/*
			panelToolbar.add(getBtnSearch(), gridBagConstraints3);
			panelToolbar.add(getBtnNext(), gridBagConstraints4);
			panelToolbar.add(getBtnPrev(), gridBagConstraints5);
			*/
			panelToolbar.add(t1, gridBagConstraintsX);
		}
		return panelToolbar;
	}

	

	/**
	 * This method initializes listLog	
	 *	
	 * @return javax.swing.JList	
	 */     
	protected javax.swing.JList getListLog() {
		if (listLog == null) {
			listLog = new javax.swing.JList();
			listLog.setDoubleBuffered(true);
            listLog.setCellRenderer(getLogPanelCellRenderer());
			listLog.setSelectionMode(javax.swing.ListSelectionModel.SINGLE_INTERVAL_SELECTION);
			listLog.setName("ListLog");
			listLog.setFont(new java.awt.Font("Default", java.awt.Font.PLAIN, 12));
			listLog.setFixedCellHeight(16);	// Significantly speeds up rendering
			listLog.addMouseListener(new java.awt.event.MouseAdapter() { 
				@Override
				public void mousePressed(java.awt.event.MouseEvent e) {
					mouseClicked(e);
				}
					
				@Override
				public void mouseReleased(java.awt.event.MouseEvent e) {
					mouseClicked(e);
				}
				
				@Override
				public void mouseClicked(java.awt.event.MouseEvent e) {
					// right mouse button action
					if ((e.getModifiers() & InputEvent.BUTTON3_MASK) != 0 || e.isPopupTrigger()) {
				    	
						// ZAP: Select history list item on right click
					    int Idx = listLog.locationToIndex( e.getPoint() );
					    if ( Idx >= 0 ) {
					    	Rectangle Rect = listLog.getCellBounds( Idx, Idx );
					    	Idx = Rect.contains( e.getPoint().x, e.getPoint().y ) ? Idx : -1;
					    }
					    if ( Idx < 0 || !listLog.getSelectionModel().isSelectedIndex( Idx ) ) {
					    	listLog.getSelectionModel().clearSelection();
					    	if ( Idx >= 0 ) {
					    		listLog.getSelectionModel().setSelectionInterval( Idx, Idx );
					    	}
					    }

				        View.getSingleton().getPopupMenu().show(e.getComponent(), e.getX(), e.getY());
				        return;
				    }	
				    
				    if ((e.getModifiers() & InputEvent.BUTTON1_MASK) != 0 && e.getClickCount() > 1) {  // double click
						requestPanel.setTabFocus();
						return;
				    }
				}
			});
			
			listLog.addListSelectionListener(new javax.swing.event.ListSelectionListener() { 

				@Override
				public void valueChanged(javax.swing.event.ListSelectionEvent e) {
					// ZAP: Changed to only display the message when there are no more selection changes.
					if (!e.getValueIsAdjusting()) {
					    if (listLog.getSelectedValue() == null) {
					        return;
					    }
	                    
						final HistoryReference historyRef = (HistoryReference) listLog.getSelectedValue();
	
	                    readAndDisplay(historyRef);
					}

				}


			});

		}
		return listLog;
	}

    
    private Vector<HistoryReference> displayQueue = new Vector<HistoryReference>();
    private Thread thread = null;
    private LogPanelCellRenderer logPanelCellRenderer = null;  //  @jve:decl-index=0:visual-constraint="10,304"
    
    
    
    protected void display(final HistoryReference historyRef) {
    	this.readAndDisplay(historyRef);
    	for (int i = 0; i < listLog.getModel().getSize(); i++) {
    		// Bit nasty, but its the only way I've found...
    		if (((HistoryReference)listLog.getModel().getElementAt(i)).getHistoryId() == historyRef.getHistoryId()) {
    			listLog.setSelectedIndex(i);
    			listLog.ensureIndexIsVisible(i);
    			break;
    			/* Doesnt work - the records are not always in order
    		} else if (((HistoryReference)listLog.getModel().getElementAt(i)).getHistoryId() > historyRef.getHistoryId()) {
    			break;
    			*/
    		}
    	}
    }

    public void clearDisplayQueue() {
    	synchronized(displayQueue) {
    		displayQueue.clear();
    	}
    }
    
    private void readAndDisplay(final HistoryReference historyRef) {

        synchronized(displayQueue) {
        	/*
        	// ZAP: Disabled the platform specific browser
            if (!ExtensionHistory.isEnableForNativePlatform() || !extension.getBrowserDialog().isVisible()) {
                // truncate queue if browser dialog is displayed to have better response
                if (displayQueue.size()>0) {
                    // replace all display queue because the newest display overrides all previous one
                    // pending to be rendered.
                    displayQueue.clear();
                }
            }
            */
            if (displayQueue.size() > 0) {
                displayQueue.clear();
            }
            
            displayQueue.add(historyRef);

        }
        
        if (thread != null && thread.isAlive()) {
            return;
        }
        
        thread = new Thread(this);

        thread.setPriority(Thread.NORM_PRIORITY);
        thread.start();
    }
    
    
    public void setDisplayPanel(HttpPanel requestPanel, HttpPanel responsePanel) {
        this.requestPanel = requestPanel;
        this.responsePanel = responsePanel;

    }
    
 private void displayMessage(HttpMessage msg) {
        
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
    }

    @Override
    public void run() {
    	   HistoryReference ref = null;
           int count = 0;
           
           do {
               synchronized(displayQueue) {
                   count = displayQueue.size();
                   if (count == 0) {
                       break;
                   }
                   
                   ref = displayQueue.get(0);
                   displayQueue.remove(0);
               }
               
               try {
                   final HistoryReference finalRef = ref;
                   final HttpMessage msg = ref.getHttpMessage();
                   EventQueue.invokeAndWait(new Runnable() {
                       @Override
                       public void run() {
                           displayMessage(msg);
                           checkAndShowBrowser(finalRef, msg);
                           listLog.requestFocus();

                       }
                   });
                   
               } catch (Exception e) {
                   // ZAP: Added logging.
                   logger.error(e.getMessage(), e);
               }
               
               // wait some time to allow another selection event to be triggered
               try {
                   Thread.sleep(200);
               } catch (Exception e) {}
           } while (true);
           
           
       }
    private void checkAndShowBrowser(HistoryReference ref, HttpMessage msg) {
    	// TODO reenable??
    	/*
        // ZAP: Disabled the platform specific browser
        if (!ExtensionHistory.isEnableForNativePlatform() || !extension.getBrowserDialog().isVisible()) {
            return;
        }
        extension.browserDisplay(ref, msg);
        */
    }

    /**
     * This method initializes logPanelCellRenderer	
     * 	
     * @return org.parosproxy.paros.extension.history.LogPanelCellRenderer	
     */
    private LogPanelCellRenderer getLogPanelCellRenderer() {
        if (logPanelCellRenderer == null) {
            logPanelCellRenderer = new LogPanelCellRenderer();
    	    if (Model.getSingleton().getOptionsParam().getViewParam().getWmUiHandlingOption() == 0) {
    	    	logPanelCellRenderer.setSize(new java.awt.Dimension(328,21));
    	    }
            logPanelCellRenderer.setBackground(java.awt.Color.white);
            logPanelCellRenderer.setFont(new java.awt.Font("MS Sans Serif", java.awt.Font.PLAIN, 12));
        }
        return logPanelCellRenderer;
    }

    public void setFilterStatus (HistoryFilter filter) {
    	filterStatus.setText(filter.toShortString());
    	filterStatus.setToolTipText(filter.toLongString());
    }

    public void newScanThread(String site, AbstractParam params, boolean inScope) {
		this.getStartScanButton().setEnabled(false);
		this.getStopScanButton().setEnabled(true);
		try {
    		new Thread(this.runnable = new SpiderThread(site, this.extension, inScope)).start();
    	} catch (Exception e) {
    		logger.error(e);
    	}
	}
    
	public void scanSite(SiteNode n, boolean inScope) {
		try {
			this.extension.run(n.getHierarchicNodeName(), inScope);
		} catch (Exception e) {
    		logger.error(e);
		}
	}
}




