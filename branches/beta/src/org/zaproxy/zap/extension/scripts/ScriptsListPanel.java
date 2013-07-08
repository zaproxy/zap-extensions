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
package org.zaproxy.zap.extension.scripts;

import java.awt.CardLayout;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.io.File;
import java.io.IOException;

import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JScrollPane;
import javax.swing.JTree;
import javax.swing.SwingUtilities;
import javax.swing.filechooser.FileFilter;
import javax.swing.tree.TreeNode;
import javax.swing.tree.TreePath;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.extension.httppanel.Message;
import org.zaproxy.zap.extension.scripts.dialogs.EditScriptDialog;
import org.zaproxy.zap.extension.scripts.dialogs.LoadScriptDialog;
import org.zaproxy.zap.extension.scripts.dialogs.NewScriptDialog;
import org.zaproxy.zap.view.LayoutHelper;

public class ScriptsListPanel extends AbstractPanel {

	public static final String TREE = "ScriptListTree";
	
	private static final long serialVersionUID = 1L;
	private static final Logger logger = Logger.getLogger(ScriptsListPanel.class);
	
	private ExtensionScripts extension = null;

	private javax.swing.JPanel listPanel = null;
	private javax.swing.JToolBar panelToolbar = null;
	private JButton loadButton = null;
	private JButton saveButton = null;
	private JButton newScriptButton = null;

	private JScrollPane jScrollPane = null;
	private JTree tree = null;

	private NewScriptDialog newScriptDialog = null;
	private LoadScriptDialog loadScriptDialog = null;
	private EditScriptDialog editScriptDialog = null;

	private HttpMessage lastMessageDisplayed = null;

	public ScriptsListPanel(ExtensionScripts extension) {
		super();
		this.extension = extension;
		initialize();
	}
	
	private void initialize() {
        this.setLayout(new CardLayout());
        this.setName(Constant.messages.getString("scripts.list.panel.title"));
		this.setIcon(ExtensionScripts.ICON);

        this.add(getListPanel(), getListPanel().getName());
			
	}

	private javax.swing.JPanel getListPanel() {
		if (listPanel == null) {

			listPanel = new javax.swing.JPanel();
			listPanel.setLayout(new GridBagLayout());
			listPanel.setName("ScriptsListPanel");
			
			listPanel.add(this.getPanelToolbar(), LayoutHelper.getGBC(0, 0, 1, 0, new Insets(2,2,2,2)));
			listPanel.add(getJScrollPane(), 
					LayoutHelper.getGBC(0, 1, 1, 1.0, 1.0, GridBagConstraints.BOTH, new Insets(2,2,2,2)));

		}
		return listPanel;
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
			panelToolbar.setName("ScriptsListToolbar");
			
			int i = 1;
			panelToolbar.add(getLoadButton(), LayoutHelper.getGBC(i++, 0, 1, 0.0D));
			panelToolbar.add(getSaveButton(), LayoutHelper.getGBC(i++, 0, 1, 0.0D));
			panelToolbar.add(getNewScriptButton(), LayoutHelper.getGBC(i++, 0, 1, 0.0D));
			panelToolbar.add(new JLabel(), LayoutHelper.getGBC(20, 0, 1, 1.0D));	// spacer
		}
		return panelToolbar;
	}

	private JButton getLoadButton() {
		if (loadButton == null) {
			loadButton = new JButton();
			loadButton.setIcon(new ImageIcon(ZAP.class.getResource("/resource/icon/16/047.png")));	// 'open folder' icon
			loadButton.setToolTipText(Constant.messages.getString("scripts.list.toolbar.button.load"));

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
			saveButton.setIcon(new ImageIcon(ZAP.class.getResource("/resource/icon/16/096.png")));	// 'diskette' icon
			saveButton.setToolTipText(Constant.messages.getString("scripts.list.toolbar.button.save"));
			saveButton.setEnabled(false);

			saveButton.addActionListener(new java.awt.event.ActionListener() { 

				@Override
				public void actionPerformed(java.awt.event.ActionEvent e) {
					ScriptWrapper script = getSelectedScript();
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
					ScriptsListPanel.class.getResource("/org/zaproxy/zap/extension/scripts/resource/icons/script-add.png")));
			newScriptButton.setToolTipText(Constant.messages.getString("scripts.list.toolbar.button.new"));
			
			newScriptButton.addActionListener(new java.awt.event.ActionListener() { 

				@Override
				public void actionPerformed(java.awt.event.ActionEvent e) {
					showNewScriptDialog();
				}

			});
		}
		return newScriptButton;
	}

	private void showNewScriptDialog() {
		if (newScriptDialog == null) {
			newScriptDialog = new NewScriptDialog(extension, View.getSingleton().getMainFrame(), new Dimension(500, 400));
		}
		newScriptDialog.reset();
		newScriptDialog.setVisible(true);
	}

	private void showLoadScriptDialog(ScriptWrapper script) {
		if (loadScriptDialog == null) {
			loadScriptDialog = new LoadScriptDialog(extension, View.getSingleton().getMainFrame(), new Dimension(500, 400));
		}
		loadScriptDialog.reset(script);
		loadScriptDialog.setVisible(true);
	}

	private void showEditScriptDialog(ScriptWrapper script) {
		if (editScriptDialog == null) {
			editScriptDialog = new EditScriptDialog(extension, View.getSingleton().getMainFrame(), new Dimension(500, 400));
		}
		editScriptDialog.init(script);
		editScriptDialog.setVisible(true);
	}

	private void saveScript (ScriptWrapper script) {
		if (script.getFile() != null) {
			try {
				extension.saveScript(script);
				this.setButtonStates();
				((ScriptTreeModel)this.getTree().getModel()).nodeChanged(this.getSelectedScriptNode());
				
			} catch (IOException e1) {
	            View.getSingleton().showWarningDialog(
	            		Constant.messages.getString("file.save.error") + " " + script.getFile().getAbsolutePath() + ".");
			}
		} else {
		    JFileChooser chooser = new JFileChooser(Model.getSingleton().getOptionsParam().getUserDirectory());
		    // ZAP: set session name as file name proposal
			chooser.setSelectedFile(new File(script.getName()));
		    chooser.setFileFilter(getScriptFilter(script.getEngine().getExtension(), script.getEngineName()));
			File file = null;
		    int rc = chooser.showSaveDialog(View.getSingleton().getMainFrame());
		    if(rc == JFileChooser.APPROVE_OPTION) {
	    		file = chooser.getSelectedFile();
	    		if (file == null) {
	    			return;
	    		}
	    		String fileName = file.getAbsolutePath();
	    		if (!fileName.endsWith(script.getEngine().getExtension())) {
	    		    fileName += script.getEngine().getExtension();
	    		    file = new File(fileName);
	    		    script.setFile(file);
	    		}
	    		
				try {
					extension.saveScript(script);
					this.setButtonStates();
					((ScriptTreeModel)this.getTree().getModel()).nodeChanged(this.getSelectedScriptNode());

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
		File file = null;
	    int rc = chooser.showOpenDialog(this);
	    if(rc == JFileChooser.APPROVE_OPTION) {
    		file = chooser.getSelectedFile();
    		if (file == null) {
    			return;
    		}
    	    try {
    	    	ScriptWrapper script = new ScriptWrapper();
    	    	script.setFile(file);
        		extension.loadScript(script);
       			// TODO Not ideal, but will require some core changes to do properly
       			showLoadScriptDialog(script);

            } catch (Exception e) {
            	logger.error(e.getMessage(), e);
	            View.getSingleton().showWarningDialog(
	            		Constant.messages.getString("file.load.error") + " " + file.getAbsolutePath());
            }
	    }
	}

	private FileFilter getScriptFilter(final String extension, final String description) {
		return new FileFilter() {
	           @Override
	           public boolean accept(File file) {
	                if (file.isDirectory()) {
	                    return true;
	                } else if (file.isFile() && file.getName().endsWith(extension)) {
	                    return true;
	                }
	                return false;
	            }
	           @Override
	           public String getDescription() {
	               return description;
	           }
	    };
	}

	protected ScriptWrapper getSelectedScript() {
	    ScriptNode node = this.getSelectedNode();
	    if (node != null) {
	    	return (ScriptWrapper)node.getUserObject();
	    }
	    return null;
	}

	protected ScriptNode getSelectedNode() {
	    return (ScriptNode) tree.getLastSelectedPathComponent();
	}

	private ScriptNode getSelectedScriptNode() {
	    ScriptNode node = (ScriptNode) tree.getLastSelectedPathComponent();
	    while (node != null && node.getUserObject() != null) {
	    	if (node.getUserObject() instanceof ScriptWrapper) {
	    		return node;
	    	}
	    	node = (ScriptNode) node.getParent();
	    }
	    return null;
	}
	
	protected void setButtonStates() {
	    ScriptNode node = (ScriptNode) tree.getLastSelectedPathComponent();
	    
	    if (node != null && node.getUserObject() instanceof ScriptWrapper) {
	    	ScriptWrapper script = (ScriptWrapper) node.getUserObject();
    		this.getSaveButton().setEnabled(script.isChanged());
	    } else {
    		this.getSaveButton().setEnabled(false);
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
			tree.setName(TREE);
			tree.setShowsRootHandles(true);
			tree.setBorder(javax.swing.BorderFactory.createEmptyBorder(0,0,0,0));
			tree.setCellRenderer(new ScriptsTreeCellRenderer(this.extension));
			
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
				    	// Its a double click - edit a script if selected
				    	ScriptNode node = getSelectedNode();
					    if (node != null && node.getUserObject() != null) {
					    	if (node.getUserObject() instanceof ScriptWrapper) {
					    		showEditScriptDialog((ScriptWrapper)node.getUserObject());
					    	}
					    }
				    }

				}
			});
			tree.addTreeSelectionListener(new javax.swing.event.TreeSelectionListener() { 
				@Override
				public void valueChanged(javax.swing.event.TreeSelectionEvent e) {
					selectionChanged();
				}
			});
		}
		return tree;
	}
	
	private void selectionChanged() {
		setButtonStates();
    	ScriptNode node = getSelectedNode();
	    if (node != null && node.getUserObject() != null) {
	    	if (node.getUserObject() instanceof ScriptWrapper) {
	    		extension.displayScript((ScriptWrapper)node.getUserObject());
	    	}
	    }
		
	}

	public void select(ScriptNode node) {
		this.getTree().setSelectionPath(new TreePath(node.getPath()));
	}

	public boolean isSelectedMessage(Message message) {
		return message != null && lastMessageDisplayed != null && (message.hashCode() == lastMessageDisplayed.hashCode());
	}
	
	public void showInTree (ScriptNode node) {
		TreeNode[] path = node.getPath();
		TreePath tp = new TreePath(path);
		getTree().setExpandsSelectedPaths(true);
		getTree().setSelectionPath(tp);
		getTree().scrollPathToVisible(tp);
	}

}
