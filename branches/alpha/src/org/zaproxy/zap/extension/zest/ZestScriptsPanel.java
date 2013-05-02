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
 *   http://www.apache.org/licenses/LICENSE-2.0 
 *   
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS, 
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
 * See the License for the specific language governing permissions and 
 * limitations under the License. 
 */
package org.zaproxy.zap.extension.zest;

import java.awt.CardLayout;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;

import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JScrollPane;
import javax.swing.JToggleButton;
import javax.swing.JTree;
import javax.swing.SwingUtilities;
import javax.swing.filechooser.FileFilter;
import javax.swing.tree.TreePath;

import org.apache.log4j.Logger;
import org.mozilla.zest.core.v1.ZestAction;
import org.mozilla.zest.core.v1.ZestAssertion;
import org.mozilla.zest.core.v1.ZestConditional;
import org.mozilla.zest.core.v1.ZestElement;
import org.mozilla.zest.core.v1.ZestRequest;
import org.mozilla.zest.core.v1.ZestScript;
import org.mozilla.zest.core.v1.ZestStatement;
import org.mozilla.zest.core.v1.ZestTransformation;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.httppanel.Message;
import org.zaproxy.zap.extension.search.SearchPanel;
import org.zaproxy.zap.extension.zest.dialogs.ZestActionDialog;
import org.zaproxy.zap.extension.zest.dialogs.ZestAssertionsDialog;
import org.zaproxy.zap.extension.zest.dialogs.ZestConditionDialog;
import org.zaproxy.zap.extension.zest.dialogs.ZestRequestDialog;
import org.zaproxy.zap.extension.zest.dialogs.ZestScriptsDialog;
import org.zaproxy.zap.extension.zest.dialogs.ZestTransformDialog;
import org.zaproxy.zap.view.LayoutHelper;

public class ZestScriptsPanel extends AbstractPanel {

	private static final long serialVersionUID = 1L;
	private static final Logger logger = Logger.getLogger(ZestScriptsPanel.class);
	
	private ExtensionZest extension = null;

	private javax.swing.JPanel zestPanel = null;
	private javax.swing.JToolBar panelToolbar = null;
	private JButton loadButton = null;
	private JButton saveButton = null;
	private JButton newScriptButton = null;
	private JButton newPscanButton = null;
	private JButton runButton = null;
	private JToggleButton pauseButton = null;
	private JButton stopButton = null;

	private JScrollPane jScrollPane = null;
	private JTree tree = null;
	
	private ZestScriptsDialog scriptDialog = null;
	private ZestRequestDialog requestDialog = null;
	private ZestAssertionsDialog assertionsDialog = null;
	private ZestActionDialog actionDialog = null;
	private ZestConditionDialog conditionDialog = null;
	private ZestTransformDialog transformationDialog = null;

	private HttpMessage lastMessageDisplayed = null;

	public ZestScriptsPanel(ExtensionZest extension) {
		super();
		this.extension = extension;
		initialize();
	}
	
	private void initialize() {
        this.setLayout(new CardLayout());
        this.setName(Constant.messages.getString("zest.scripts.panel.title"));
		this.setIcon(ExtensionZest.ZEST_ICON);

        //this.add(getSplitPane(), getSplitPane().getName());
        this.add(getZestPanel(), getZestPanel().getName());
			
	}

	private javax.swing.JPanel getZestPanel() {
		if (zestPanel == null) {

			zestPanel = new javax.swing.JPanel();
			zestPanel.setLayout(new GridBagLayout());
			zestPanel.setName("ZestPanel");
			
			zestPanel.add(this.getPanelToolbar(), LayoutHelper.getGBC(0, 0, 1, 0, new Insets(2,2,2,2)));
			zestPanel.add(getJScrollPane(), 
					LayoutHelper.getGBC(0, 1, 1, 1.0, 1.0, GridBagConstraints.BOTH, new Insets(2,2,2,2)));

		}
		return zestPanel;
	}

	private javax.swing.JToolBar getPanelToolbar() {
		if (panelToolbar == null) {
			
			panelToolbar = new javax.swing.JToolBar();
			panelToolbar.setLayout(new GridBagLayout());
			panelToolbar.setEnabled(true);
			panelToolbar.setFloatable(false);
			panelToolbar.setRollover(true);
			panelToolbar.setPreferredSize(new Dimension(800,30));
			panelToolbar.setFont(new java.awt.Font("Dialog", java.awt.Font.PLAIN, 12));
			panelToolbar.setName("ZestToolbar");
			
			int i = 1;
			panelToolbar.add(getLoadButton(), LayoutHelper.getGBC(i++, 0, 1, 0.0D));
			panelToolbar.add(getSaveButton(), LayoutHelper.getGBC(i++, 0, 1, 0.0D));
			panelToolbar.add(getNewScriptButton(), LayoutHelper.getGBC(i++, 0, 1, 0.0D));
			panelToolbar.add(getNewPscanButton(), LayoutHelper.getGBC(i++, 0, 1, 0.0D));
			panelToolbar.add(getRunButton(), LayoutHelper.getGBC(i++, 0, 1, 0.0D));
			panelToolbar.add(getPauseButton(), LayoutHelper.getGBC(i++, 0, 1, 0.0D));
			panelToolbar.add(getStopButton(), LayoutHelper.getGBC(i++, 0, 1, 0.0D));
			panelToolbar.add(new JLabel(), LayoutHelper.getGBC(20, 0, 1, 1.0D));	// spacer
		}
		return panelToolbar;
	}

	private JButton getLoadButton() {
		if (loadButton == null) {
			loadButton = new JButton();
			loadButton.setIcon(new ImageIcon(SearchPanel.class.getResource("/resource/icon/16/047.png")));	// 'open folder' icon
			loadButton.setToolTipText(Constant.messages.getString("zest.toolbar.button.load"));

			loadButton.addActionListener(new java.awt.event.ActionListener() { 
				@Override
				public void actionPerformed(java.awt.event.ActionEvent e) {
					loadScript();
				}
			});
		}
		return loadButton;
	}

	private JButton getSaveButton() {
		if (saveButton == null) {
			saveButton = new JButton();
			saveButton.setIcon(new ImageIcon(SearchPanel.class.getResource("/resource/icon/16/096.png")));	// 'diskette' icon
			saveButton.setToolTipText(Constant.messages.getString("zest.toolbar.button.save"));
			saveButton.setEnabled(false);

			saveButton.addActionListener(new java.awt.event.ActionListener() { 

				@Override
				public void actionPerformed(java.awt.event.ActionEvent e) {
					ZestScriptWrapper script = getSelectedScript();
					if (script == null) {
						return;
					}
					saveScript(script);
				}
			});
		}
		return saveButton;
	}
	
	private JButton getNewScriptButton() {
		if (newScriptButton == null) {
			newScriptButton = new JButton();
			newScriptButton.setIcon(new ImageIcon(
					ZestScriptsPanel.class.getResource("/org/zaproxy/zap/extension/zest/resource/zest-script-add.png")));
			newScriptButton.setToolTipText(Constant.messages.getString("zest.toolbar.button.new.targeted"));
			
			newScriptButton.addActionListener(new java.awt.event.ActionListener() { 

				@Override
				public void actionPerformed(java.awt.event.ActionEvent e) {
					showZestEditScriptDialog(null, false);
				}
			});
		}
		return newScriptButton;
	}

	private JButton getNewPscanButton() {
		if (newPscanButton == null) {
			newPscanButton = new JButton();
			newPscanButton.setIcon(new ImageIcon(
					ZestScriptsPanel.class.getResource("/org/zaproxy/zap/extension/zest/resource/zest-pscan-add.png")));
			newPscanButton.setToolTipText(Constant.messages.getString("zest.toolbar.button.new.passive"));
			
			newPscanButton.addActionListener(new java.awt.event.ActionListener() { 

				@Override
				public void actionPerformed(java.awt.event.ActionEvent e) {
					showZestEditScriptDialog(null, true);
				}
			});
		}
		return newPscanButton;
	}

	private JButton getRunButton() {
		if (runButton == null) {
			runButton = new JButton();
			runButton.setIcon(new ImageIcon(SearchPanel.class.getResource("/resource/icon/16/131.png")));	// 'play' icon
			runButton.setToolTipText(Constant.messages.getString("zest.toolbar.button.run"));
			runButton.setEnabled(false);

			runButton.addActionListener(new java.awt.event.ActionListener() { 

				@Override
				public void actionPerformed(java.awt.event.ActionEvent e) {
					ZestScript zest = getSelectedScript();
					if (zest != null) {
						extension.runScript(zest);
						setButtonStates();
					}
				}
			});
		}
		return runButton;
	}
	
	private JToggleButton getPauseButton() {
		if (pauseButton == null) {
			pauseButton = new JToggleButton();
			pauseButton.setIcon(new ImageIcon(SearchPanel.class.getResource("/resource/icon/16/141.png")));	// 'pause' icon
			pauseButton.setToolTipText(Constant.messages.getString("zest.toolbar.button.pause"));
			pauseButton.setEnabled(false);
			pauseButton.setSelected(false);

			pauseButton.addActionListener(new java.awt.event.ActionListener() { 

				@Override
				public void actionPerformed(java.awt.event.ActionEvent e) {
					if (extension.isScriptPaused()) {
						extension.resumeScript();
					} else {
						extension.pauseScript();
					}
					setButtonStates();
				}
			});
		}
		return pauseButton;
	}
	
	private JButton getStopButton() {
		if (stopButton == null) {
			stopButton = new JButton();
			stopButton.setIcon(new ImageIcon(SearchPanel.class.getResource("/resource/icon/16/142.png")));	// 'stop' icon (blue square)
			stopButton.setToolTipText(Constant.messages.getString("zest.toolbar.button.stop"));
			stopButton.setEnabled(false);

			stopButton.addActionListener(new java.awt.event.ActionListener() { 

				@Override
				public void actionPerformed(java.awt.event.ActionEvent e) {
					extension.stopScript();
					setButtonStates();
				}
			});
		}
		return stopButton;
	}
	
	private FileFilter getZestFilter() {
		return new FileFilter() {
	           @Override
	           public boolean accept(File file) {
	                if (file.isDirectory()) {
	                    return true;
	                } else if (file.isFile() && file.getName().endsWith(".zst")) {
	                    return true;
	                }
	                return false;
	            }
	           @Override
	           public String getDescription() {
	        	   // ZAP: Rebrand
	               return Constant.messages.getString("zest.format.zest.script");
	           }
	    };
	}
	
	private void saveScript (ZestScriptWrapper script) {
		if (script.getFile() != null) {
			try {
				extension.saveScript(script, script.getFile());
				this.setButtonStates();
				((ZestTreeModel)this.getTree().getModel()).nodeChanged(this.getSelectedScriptNode());
				
			} catch (IOException e1) {
	            View.getSingleton().showWarningDialog(
	            		Constant.messages.getString("file.save.error") + " " + script.getFile().getAbsolutePath() + ".");
			}
		} else {
		    JFileChooser chooser = new JFileChooser(Model.getSingleton().getOptionsParam().getUserDirectory());
		    // ZAP: set session name as file name proposal
			chooser.setSelectedFile(new File(script.getTitle()));
		    chooser.setFileFilter(getZestFilter());
			File file = null;
		    int rc = chooser.showSaveDialog(View.getSingleton().getMainFrame());
		    if(rc == JFileChooser.APPROVE_OPTION) {
	    		file = chooser.getSelectedFile();
	    		if (file == null) {
	    			return;
	    		}
	    		String fileName = file.getAbsolutePath();
	    		if (!fileName.endsWith(".zst")) {
	    		    fileName += ".zst";
	    		    file = new File(fileName);
	    		}
	    		
				try {
					extension.saveScript(script, file);
					this.setButtonStates();
					((ZestTreeModel)this.getTree().getModel()).nodeChanged(this.getSelectedScriptNode());

				} catch (IOException e1) {
		            View.getSingleton().showWarningDialog(
		            		Constant.messages.getString("file.save.error") + " " + file.getAbsolutePath() + ".");
				}
		    }
		}
	}
	
	private void loadScript() {
		String dir = Model.getSingleton().getOptionsParam().getUserDirectory().getAbsolutePath();
		
	    JFileChooser chooser = new JFileChooser(dir);
	    chooser.setFileFilter(getZestFilter());
		File file = null;
	    int rc = chooser.showOpenDialog(this);
	    if(rc == JFileChooser.APPROVE_OPTION) {
    		file = chooser.getSelectedFile();
    		if (file == null) {
    			return;
    		}
    	    try {
        		ZestScriptWrapper script = extension.loadScript(file);
        		if (script != null) {
        			extension.add(script);
        		}

            } catch (Exception e) {
            	logger.error(e.getMessage(), e);
	            View.getSingleton().showWarningDialog(
	            		Constant.messages.getString("file.load.error") + " " + file.getAbsolutePath());
            }
	    }
	}

	
	private ZestScriptWrapper getSelectedScript() {
	    ZestNode node = (ZestNode) tree.getLastSelectedPathComponent();
	    while (node != null && node.getZestElement() != null) {
	    	if (node.getZestElement() instanceof ZestScript) {
	    		return (ZestScriptWrapper)node.getZestElement();
	    	}
	    	node = (ZestNode) node.getParent();
	    }
	    return null;
	}

	protected ZestNode getSelectedNode() {
	    return (ZestNode) tree.getLastSelectedPathComponent();
	}

	private ZestNode getSelectedScriptNode() {
	    ZestNode node = (ZestNode) tree.getLastSelectedPathComponent();
	    while (node != null && node.getZestElement() != null) {
	    	if (node.getZestElement() instanceof ZestScript) {
	    		return node;
	    	}
	    	node = (ZestNode) node.getParent();
	    }
	    return null;
	}
	
	protected void setButtonStates() {
	    ZestNode node = (ZestNode) tree.getLastSelectedPathComponent();
	    if (node != null && node.getZestElement() != null &&
	    		! node.getParent().isRoot()) {
	    	// Only enable if a targeted script has been selected
	    	if (node.isChildOf(ZestTreeElement.Type.TARGETED_SCRIPT)) {
	    		this.getRunButton().setEnabled(true);
	    	}
	        // Only enable the save button if the script has been updated
	        while (node != null) {
	        	if (node.getZestElement() instanceof ZestScriptWrapper) {
	    	        this.getSaveButton().setEnabled(((ZestScriptWrapper)node.getZestElement()).isUpdated());
	    	        break;
	        	}
	        	node = (ZestNode) node.getParent();
	        }
	    } else {
	        this.getRunButton().setEnabled(false);
	        this.getStopButton().setEnabled(false);
	        this.getSaveButton().setEnabled(false);
	    }
	    
	    if (this.extension.isScriptRunning()) {
	        this.getRunButton().setEnabled(false);
	        this.getStopButton().setEnabled(true);
	        this.getPauseButton().setEnabled(true);
	    } else {
	        this.getStopButton().setEnabled(false);
	        this.getPauseButton().setEnabled(false);
	        this.getPauseButton().setSelected(false);
	    }
	}

	private JScrollPane getJScrollPane() {
		if (jScrollPane == null) {
			jScrollPane = new JScrollPane();
			jScrollPane.setFont(new java.awt.Font("Dialog", java.awt.Font.PLAIN, 11));
			jScrollPane.setHorizontalScrollBarPolicy(javax.swing.JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
			jScrollPane.setViewportView(getTree());
		}
		return jScrollPane;
	}

	JTree getTree() {
		if (tree == null) {
			tree = new JTree();
			tree.setModel(extension.getTreeModel());
			tree.setName("ZestTree");
			tree.setShowsRootHandles(true);
			tree.setBorder(javax.swing.BorderFactory.createEmptyBorder(0,0,0,0));
			tree.setCellRenderer(new ZestTreeCellRenderer());
			
			tree.addMouseListener(new java.awt.event.MouseAdapter() { 
				@Override
				public void mousePressed(java.awt.event.MouseEvent e) {
				}
					
				@Override
				public void mouseReleased(java.awt.event.MouseEvent e) {
					mouseClicked(e);
				}
				
				@Override
				public void mouseClicked(java.awt.event.MouseEvent e) {
					// right mouse button action
				    if (SwingUtilities.isRightMouseButton(e)) {
						// Select site list item on right click
				    	TreePath tp = tree.getPathForLocation( e.getPoint().x, e.getPoint().y );
				    	if ( tp != null ) {
				    		boolean select = true;
				    		// Only select a new item if the current item is not
				    		// already selected - this is to allow multiple items
				    		// to be selected
					    	if (tree.getSelectionPaths() != null) {
					    		for (TreePath t : tree.getSelectionPaths()) {
					    			if (t.equals(tp)) {
					    				select = false;
					    				break;
					    			}
					    		}
					    	}
					    	if (select) {
					    		tree.getSelectionModel().setSelectionPath(tp);
					    	}
				    	}
				        View.getSingleton().getPopupMenu().show(e.getComponent(), e.getX(), e.getY());

				    }
				    
				    if (e.getClickCount() > 1) {
				    	// Its a double click - edit the node
					    ZestNode node = (ZestNode) tree.getLastSelectedPathComponent();
					    if (node != null && node.getZestElement() != null && ! node.isShadow()) {
					        Object obj = node.getZestElement();
					        ZestNode parent = (ZestNode)node.getParent();
					        if (obj instanceof ZestScriptWrapper) {
					        	showZestEditScriptDialog((ZestScriptWrapper) obj, 
					        			ZestTreeElement.Type.PASSIVE_SCRIPT.equals(parent.getTreeType()));
					        } else if (obj instanceof ZestRequest) {
					        	showZestEditRequestDialog(
					        			extension.getScriptWrapper(node), (ZestRequest) obj);
					        } else if (obj instanceof ZestAssertion) {
					        	showZestAssertionDialog(
					        			(ZestRequest)parent.getZestElement(), (ZestAssertion) obj, false);
					        } else if (obj instanceof ZestAction) {
					        	showZestActionDialog(
					        			parent, null, (ZestAction) obj, false);
					        } else if (obj instanceof ZestConditional) {
					        	showZestConditionalDialog(
					        			parent, null, (ZestConditional) obj, false);
					        } else if (obj instanceof ZestTransformation) {
					        	showZestTransformationDialog(
					        			extension.getScriptWrapper(node), 
					        			(ZestNode)node.getParent(), 
					        			(ZestTransformation) obj, false);
					        }  
					    }
				    }

				}
			});
			tree.addTreeSelectionListener(new javax.swing.event.TreeSelectionListener() { 
				@Override
				public void valueChanged(javax.swing.event.TreeSelectionEvent e) {
					setButtonStates();
					refreshMessage();
				}
			});
		}
		return tree;
	}

    protected void refreshMessage() {
	    ZestNode node = (ZestNode) tree.getLastSelectedPathComponent();
	    if (node != null && node.getZestElement() != null) {
	        ZestElement ze = node.getZestElement();
	        if (ze instanceof ZestRequest) {
	        	displayMessage((ZestRequest)ze); 
	        } else {
	        	clearMessage();
	        }
	    }
    }

    private void displayMessage(ZestRequest ze) {
		try {
			lastMessageDisplayed = ZestZapUtils.toHttpMessage(ze, ze.getResponse());
			
	    	if (lastMessageDisplayed.getRequestHeader() != null) {
	    		logger.debug("displayMessage " + lastMessageDisplayed.getRequestHeader().getURI());
	    	} else {
	    		logger.debug("displayMessage null header");
	    	}
	    	
	        if (lastMessageDisplayed.getRequestHeader() != null && lastMessageDisplayed.getRequestHeader().isEmpty()) {
	            View.getSingleton().getRequestPanel().clearView(true);
	        } else {
	        	View.getSingleton().getRequestPanel().setMessage(lastMessageDisplayed);
	        }
	        
	        if (lastMessageDisplayed.getResponseHeader() != null && lastMessageDisplayed.getResponseHeader().isEmpty()) {
	        	View.getSingleton().getResponsePanel().clearView(false);
	        } else {
	        	View.getSingleton().getResponsePanel().setMessage(lastMessageDisplayed, true);
	        }
		} catch (Exception e) {
			logger.error(e.getMessage(), e);
		}
    }
    
    private void clearMessage() {
        View.getSingleton().getRequestPanel().clearView(true);
    	View.getSingleton().getResponsePanel().clearView(false);
    	this.lastMessageDisplayed = null;
    }

	protected void showZestEditScriptDialog(ZestScriptWrapper script, boolean pscan) {
		this.showZestEditScriptDialog(script, pscan, null);
	}

	protected void showZestEditScriptDialog(ZestScriptWrapper script, boolean pscan, String prefix) {
		if (scriptDialog == null) {
			scriptDialog = new ZestScriptsDialog(extension, View.getSingleton().getMainFrame(), new Dimension(500, 500));
		} else if (scriptDialog.isVisible()) {
			// Already being displayed, dont overwrite anything
			return;
		}
		if (script == null) {
			script = new ZestScriptWrapper("", "", pscan ? ZestScript.Type.Passive : ZestScript.Type.Targeted);
			try {
				script.setPrefix(prefix);
			} catch (MalformedURLException e) {
				logger.error(e.getMessage(), e);
			}
			scriptDialog.init(script, true, pscan);
		} else {
			scriptDialog.init(script, false, pscan);
		}
		scriptDialog.setVisible(true);
	}
	
	private void showZestEditRequestDialog(ZestScriptWrapper script, ZestRequest request) {
		if (requestDialog == null) {
			requestDialog = new ZestRequestDialog(extension, View.getSingleton().getMainFrame(), new Dimension(500, 700));
		} else if (requestDialog.isVisible()) {
			// Already being displayed, dont overwrite anything
			return;
		} else {
		}
		requestDialog.init(script, request);
		requestDialog.setVisible(true);
	}


	protected void showZestAssertionDialog(ZestRequest req, ZestAssertion assertion, boolean add) {
		if (assertionsDialog == null) {
			assertionsDialog = new ZestAssertionsDialog(extension, View.getSingleton().getMainFrame(), new Dimension(300, 200));
		} else if (assertionsDialog.isVisible()) {
			// Already being displayed, dont overwrite anything
			return;
		}
		assertionsDialog.init(req, assertion, add);
		assertionsDialog.setVisible(true);
	}

	protected void showZestActionDialog(ZestNode parent, ZestRequest req, ZestAction action, boolean add) {
		if (actionDialog == null) {
			actionDialog = new ZestActionDialog(extension, View.getSingleton().getMainFrame(), new Dimension(300, 200));
		} else if (actionDialog.isVisible()) {
			// Already being displayed, dont overwrite anything
			return;
		}
		actionDialog.init(parent, req, action, add);
		actionDialog.setVisible(true);
	}

	protected void showZestConditionalDialog(ZestNode parent, ZestStatement stmt, ZestConditional condition, boolean add) {
		if (conditionDialog == null) {
			conditionDialog = new ZestConditionDialog(extension, View.getSingleton().getMainFrame(), new Dimension(300, 200));
		} else if (conditionDialog.isVisible()) {
			// Already being displayed, dont overwrite anything
			return;
		}
		conditionDialog.init(parent, stmt, condition, add);
		conditionDialog.setVisible(true);
	}

	protected void showZestTransformationDialog(ZestScript script, ZestNode req, ZestTransformation transform, boolean add) {
		if (transformationDialog == null) {
			transformationDialog = new ZestTransformDialog(extension, View.getSingleton().getMainFrame(), new Dimension(400, 250));
		} else if (transformationDialog.isVisible()) {
			// Already being displayed, dont overwrite anything
			return;
		}
		transformationDialog.init(script, req, transform, add);
		transformationDialog.setVisible(true);
	}

	protected void addDeferedNode(SiteNode sn) {
		scriptDialog.addDeferedNode(sn);
	}

	public void expand(ZestNode node) {
		TreePath path = new TreePath(node.getPath());
		this.getTree().expandPath(path);
		this.getTree().setSelectionPath(path);
	}
	
	public void select(ZestNode node) {
		this.getTree().setSelectionPath(new TreePath(node.getPath()));
	}

	public boolean isSelectedMessage(Message message) {
		return message != null && lastMessageDisplayed != null && (message.hashCode() == lastMessageDisplayed.hashCode());
	}
}
