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
import java.awt.CardLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.ItemEvent;
import java.util.ResourceBundle;

import javax.swing.BorderFactory;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.SortOrder;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.view.AbstractParamPanel;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.selenium.BrowsersComboBoxModel;
import org.zaproxy.zap.utils.ZapNumberSpinner;
import org.zaproxy.zap.view.AbstractMultipleOptionsTablePanel;

public class OptionsAjaxSpider extends AbstractParamPanel {

	private static final long serialVersionUID = -1350537974139536669L;
	
	private AjaxSpiderMultipleOptionsPanel elemsOptionsPanel;
	
	private OptionsAjaxSpiderTableModel ajaxSpiderClickModel = null;

	private JPanel panelCrawljax = null;
	private final BrowsersComboBoxModel browsersComboBoxModel;
	private ZapNumberSpinner txtNumBro = null;
	private ZapNumberSpinner maximumDepthNumberSpinner = null;
	private ZapNumberSpinner maximumStatesNumberSpinner = null;
	private ZapNumberSpinner durationNumberSpinner = null;
	private ZapNumberSpinner eventWaitNumberSpinner = null;
	private ZapNumberSpinner reloadWaitNumberSpinner = null;
	    
	private JCheckBox clickDefaultElems = null;
	private JCheckBox clickElemsOnce = null;
	private JCheckBox randomInputs = null;

	private JLabel browsers = null;
	private JLabel depth = null;
	private JLabel crawlStates = null;
	private JLabel maxDuration = null;
	private JLabel eventWait = null;
	private JLabel reloadWait = null;

	private ResourceBundle resourceBundle;

    public OptionsAjaxSpider(ResourceBundle resourceBundle, BrowsersComboBoxModel browsersComboBoxModel) {
        super();
        this.resourceBundle = resourceBundle;
        this.browsersComboBoxModel = browsersComboBoxModel;

 		initialize();
   }
    
	/**
	 * This method initializes this
	 * 
	 */
	private void initialize() {
        this.setLayout(new CardLayout());
        this.setName(resourceBundle.getString("spiderajax.options.title"));
	    if (Model.getSingleton().getOptionsParam().getViewParam().getWmUiHandlingOption() == 0) {
	    	this.setSize(391, 320);
	    }
        this.add(getPanelCrawljax(), getPanelCrawljax().getName()); 
	}
	
	/**
	 * This method initializes txtNumBro	
	 * 	
	 * @return org.zaproxy.zap.utils.ZapNumberSpinner	
	 */    
	private ZapNumberSpinner getTxtNumBro() {
		if (txtNumBro == null) {
			txtNumBro = new ZapNumberSpinner(1, 1, Integer.MAX_VALUE);
		}
		return txtNumBro;
	}
   
	private ZapNumberSpinner getMaximumDepthNumberSpinner() {
		if (maximumDepthNumberSpinner == null) {
			maximumDepthNumberSpinner = new ZapNumberSpinner(0, 10, Integer.MAX_VALUE);
		}
		return maximumDepthNumberSpinner;
	}
	
	 private ZapNumberSpinner getMaximumStatesNumberSpinner() {
		if (maximumStatesNumberSpinner == null) {
			maximumStatesNumberSpinner = new ZapNumberSpinner(0, 0, Integer.MAX_VALUE);
		}
		return maximumStatesNumberSpinner;
	}
	
	private ZapNumberSpinner getDurationNumberSpinner() {
		if (durationNumberSpinner == null) {
			durationNumberSpinner = new ZapNumberSpinner(0, 60, Integer.MAX_VALUE);
		}
		return durationNumberSpinner;
	}
	

	private ZapNumberSpinner getEventWaitNumberSpinner() {
		if (eventWaitNumberSpinner == null) {
			eventWaitNumberSpinner = new ZapNumberSpinner(1, 1000, Integer.MAX_VALUE);
		}
		return eventWaitNumberSpinner;
	}
 
	private ZapNumberSpinner getReloadWaitNumberSpinner() {
		if (reloadWaitNumberSpinner == null) {
			reloadWaitNumberSpinner = new ZapNumberSpinner(1, 1000, Integer.MAX_VALUE);
		}
		return reloadWaitNumberSpinner;
	}
	

	private JCheckBox getClickDefaultElems() {
			if (clickDefaultElems == null) {
				clickDefaultElems = new JCheckBox();
				clickDefaultElems.setText(resourceBundle.getString("spiderajax.proxy.local.label.defaultElems"));
				clickDefaultElems.addItemListener(new java.awt.event.ItemListener() {
					@Override
					public void itemStateChanged(java.awt.event.ItemEvent e) {
						setClickElemsEnabled(ItemEvent.DESELECTED == e.getStateChange());
					}
				});
			}
			return clickDefaultElems;
		}
	
	private JCheckBox getClickElemsOnce() {
		if (clickElemsOnce == null) {
			clickElemsOnce = new JCheckBox();
			clickElemsOnce.setText(resourceBundle.getString("spiderajax.options.label.clickonce"));
		}
		return clickElemsOnce;
	}
	
	private JCheckBox getRandomInputs() {
		if (randomInputs == null) {
			randomInputs = new JCheckBox();
			randomInputs.setText(resourceBundle.getString("spiderajax.options.label.randominputs"));
		}
		return randomInputs;
	}
	

	/**
	 * 
	 */
	@Override
	public void initParam(Object obj) {
	    
	    OptionsParam optionsParam = (OptionsParam) obj;
	    AjaxSpiderParam ajaxSpiderParam = (AjaxSpiderParam) optionsParam.getParamSet(AjaxSpiderParam.class);
	    getAjaxSpiderClickModel().setElems(ajaxSpiderParam.getElems());
	    elemsOptionsPanel.setRemoveWithoutConfirmation(!ajaxSpiderParam.isConfirmRemoveElem());
	    
	    txtNumBro.setValue(Integer.valueOf(ajaxSpiderParam.getNumberOfBrowsers()));
	    maximumDepthNumberSpinner.setValue(Integer.valueOf(ajaxSpiderParam.getMaxCrawlDepth()));
	    maximumStatesNumberSpinner.setValue(Integer.valueOf(ajaxSpiderParam.getMaxCrawlStates()));
	    durationNumberSpinner.setValue(Integer.valueOf(ajaxSpiderParam.getMaxDuration()));
	    eventWaitNumberSpinner.setValue(Integer.valueOf(ajaxSpiderParam.getEventWait()));
	    reloadWaitNumberSpinner.setValue(Integer.valueOf(ajaxSpiderParam.getReloadWait()));
	   
	    getClickDefaultElems().setSelected(ajaxSpiderParam.isClickDefaultElems());
	    getClickElemsOnce().setSelected(ajaxSpiderParam.isClickElemsOnce());
	    getRandomInputs().setSelected(ajaxSpiderParam.isRandomInputs());
	    
	    setClickElemsEnabled(!ajaxSpiderParam.isClickDefaultElems());

		browsersComboBoxModel.setSelectedBrowser(ajaxSpiderParam.getBrowserId());
	}
	
	/**
	 * This method validates the parameters before saving them.
	 */
	@Override
	public void validateParam(Object obj) throws Exception {
	}

	@Override
	public void saveParam(Object obj) throws Exception  {; 
		OptionsParam optionsParam = (OptionsParam) obj;
		AjaxSpiderParam ajaxSpiderParam = (AjaxSpiderParam) optionsParam.getParamSet(AjaxSpiderParam.class);
		
		ajaxSpiderParam.setClickElemsOnce(getClickElemsOnce().isSelected());
		ajaxSpiderParam.setClickDefaultElems(getClickDefaultElems().isSelected());
		ajaxSpiderParam.setRandomInputs(getRandomInputs().isSelected());
		ajaxSpiderParam.setNumberOfBrowsers(txtNumBro.getValue().intValue());
		ajaxSpiderParam.setMaxCrawlDepth(maximumDepthNumberSpinner.getValue().intValue());
		ajaxSpiderParam.setMaxCrawlStates(maximumStatesNumberSpinner.getValue().intValue());
		ajaxSpiderParam.setMaxDuration(durationNumberSpinner.getValue().intValue());
		ajaxSpiderParam.setEventWait(eventWaitNumberSpinner.getValue().intValue());
		ajaxSpiderParam.setReloadWait(reloadWaitNumberSpinner.getValue().intValue());
		ajaxSpiderParam.setElems(getAjaxSpiderClickModel().getElements());

		ajaxSpiderParam.setBrowserId(browsersComboBoxModel.getSelectedItem().getBrowser().getId());
	}

	/**
	 * This method initializes panelAjaxProxy
	 * 	
	 * @return javax.swing.JPanel	
	 */    
	private JPanel getPanelCrawljax() {
		if (panelCrawljax == null) {
			panelCrawljax = new JPanel(new BorderLayout());
			
			panelCrawljax.setSize(75,100);
			
			panelCrawljax.setName("");
			
			browsers = new JLabel(resourceBundle.getString("spiderajax.options.label.browsers"));
			depth = new JLabel(resourceBundle.getString("spiderajax.options.label.depth"));
			crawlStates = new JLabel(resourceBundle.getString("spiderajax.options.label.crawlstates"));
			maxDuration  = new JLabel(resourceBundle.getString("spiderajax.options.label.maxduration"));
			eventWait = new JLabel(resourceBundle.getString("spiderajax.options.label.eventwait"));
			reloadWait = new JLabel(resourceBundle.getString("spiderajax.options.label.reloadwait"));

			GridBagConstraints gbc = new GridBagConstraints();
			
			JPanel innerPanel = new JPanel(new GridBagLayout());

			//Browser Type Option
			gbc.gridx = 0;
			gbc.gridy =0;
			gbc.weightx = 1.0;
			gbc.weighty = 1.0;
			gbc.gridwidth = 2;
			gbc.insets = new java.awt.Insets(2,2,2,2);
			gbc.anchor = GridBagConstraints.LINE_START;
			innerPanel.add(new JLabel(resourceBundle.getString("spiderajax.proxy.local.label.browsers")), gbc);
			
			gbc.gridy++;
			gbc.gridwidth = 1;
			innerPanel.add(new JComboBox<>(browsersComboBoxModel), gbc);

			//Number of browsers Option
			gbc.gridy++;
			gbc.gridx = 0;
			gbc.fill = GridBagConstraints.HORIZONTAL;
			innerPanel.add(browsers, gbc);

			gbc.gridx = 1;
			gbc.anchor = GridBagConstraints.LINE_END;
			innerPanel.add(getTxtNumBro(), gbc);
			
			//Max Crawl Depth Option
			gbc.gridx = 0;
			gbc.gridy++;
			
			gbc.anchor = GridBagConstraints.LINE_START;
			innerPanel.add(depth, gbc);
				
			gbc.gridx = 1;
			gbc.anchor = GridBagConstraints.LINE_END;
			innerPanel.add(getMaximumDepthNumberSpinner(), gbc);
			
			//Max Crawl States Option
			gbc.gridx = 0;
			gbc.gridy++;
			gbc.anchor = GridBagConstraints.LINE_START;
			innerPanel.add(crawlStates, gbc);
			
			gbc.gridx = 1;
			gbc.anchor = GridBagConstraints.LINE_END;
			innerPanel.add(getMaximumStatesNumberSpinner(), gbc);
			
			
			//Max Crawl Duration Option
			gbc.gridx = 0;
			gbc.gridy++;
			gbc.anchor = GridBagConstraints.LINE_START;
			innerPanel.add(maxDuration, gbc);
			
			gbc.gridx = 1;
			gbc.anchor = GridBagConstraints.LINE_END;
			innerPanel.add(getDurationNumberSpinner(), gbc);
		
				
			//Max Event Wait Option
			gbc.gridx = 0;
			gbc.gridy++;
			gbc.anchor = GridBagConstraints.LINE_START;
			innerPanel.add(eventWait, gbc);
									
			gbc.gridx = 1;
			gbc.anchor = GridBagConstraints.LINE_END;
			innerPanel.add(getEventWaitNumberSpinner(), gbc);
			
			//Max Reload Wait Option
			gbc.gridx = 0;
			gbc.gridy++;
			gbc.anchor = GridBagConstraints.LINE_START;
			innerPanel.add(reloadWait , gbc);
			
			gbc.gridx = 1;
			gbc.anchor = GridBagConstraints.LINE_END;
			innerPanel.add(getReloadWaitNumberSpinner(), gbc);
			
			//Click Once Option
			gbc.gridx = 0;
			gbc.gridy++;
			gbc.anchor = GridBagConstraints.LINE_START;
			innerPanel.add(getClickElemsOnce(), gbc);
			
			//Random Inputs Option
			gbc.gridy++;
			gbc.anchor = GridBagConstraints.LINE_START;
			innerPanel.add(getRandomInputs(), gbc);
			
			//Click Default Elements
			gbc.gridy++;
			gbc.gridwidth = 2;
			innerPanel.add(getClickDefaultElems(), gbc);
			
			//Select Elements to Click
			gbc.gridy++;
			gbc.insets = new java.awt.Insets(16,2,2,2);
			innerPanel.add(new JLabel(resourceBundle.getString("spiderajax.options.label.clickelems")),gbc);
			
			elemsOptionsPanel = new AjaxSpiderMultipleOptionsPanel(getAjaxSpiderClickModel());
			gbc.gridy++;
			gbc.weighty = 1.0D;
			gbc.insets = new java.awt.Insets(2,2,2,2);
			innerPanel.add(elemsOptionsPanel, gbc);
			
			JScrollPane scrollPane = new JScrollPane(innerPanel);
			scrollPane.setBorder(BorderFactory.createEmptyBorder());
			
			panelCrawljax.add(scrollPane,BorderLayout.CENTER);

		}
		
		return panelCrawljax;
	}
	
	private OptionsAjaxSpiderTableModel getAjaxSpiderClickModel() {
		if (ajaxSpiderClickModel == null) {
			ajaxSpiderClickModel = new OptionsAjaxSpiderTableModel();
		}
		return ajaxSpiderClickModel;
	}
	
	/**
	 * @return the help file of the plugin
	 */
	@Override
	public String getHelpIndex() {
		return "addon.spiderajax.options";
	}
	
	
	private AjaxSpiderMultipleOptionsPanel getAjaxSpiderClickPanel() {
		if (elemsOptionsPanel == null) {
			elemsOptionsPanel = new AjaxSpiderMultipleOptionsPanel(getAjaxSpiderClickModel());
		}
		return elemsOptionsPanel;
	}

	private void setClickElemsEnabled(boolean isEnabled) {
		getAjaxSpiderClickPanel().setComponentEnabled(isEnabled);
	}
	
	private static class AjaxSpiderMultipleOptionsPanel extends AbstractMultipleOptionsTablePanel<AjaxSpiderParamElem> {
       
        private static final long serialVersionUID = -115340627058929308L;
        
        private static final String REMOVE_DIALOG_TITLE = Constant.messages.getString("spiderajax.options.dialog.elem.remove.title");
	    private static final String REMOVE_DIALOG_TEXT = Constant.messages.getString("spiderajax.options.dialog.elem.remove.text");
	    
	    private static final String REMOVE_DIALOG_CONFIRM_BUTTON_LABEL = Constant.messages.getString("spiderajax.options.dialog.elem.remove.button.confirm");
	    private static final String REMOVE_DIALOG_CANCEL_BUTTON_LABEL = Constant.messages.getString("spiderajax.options.dialog.elem.remove.button.cancel");
	    
	    private static final String REMOVE_DIALOG_CHECKBOX_LABEL = Constant.messages.getString("spiderajax.options.dialog.elem.remove.checkbox.label");
	    
	    private DialogAddElem addDialog = null;
        private DialogModifyElem modifyDialog = null;
        
        private OptionsAjaxSpiderTableModel model;
        
        public AjaxSpiderMultipleOptionsPanel(OptionsAjaxSpiderTableModel model) {
            super(model);
            
            this.model = model;
            
            getTable().getColumnExt(0).setPreferredWidth(5);
            getTable().setSortOrder(1, SortOrder.ASCENDING);
            getTable().setVisibleRowCount(5);
        }

        @Override
        public AjaxSpiderParamElem showAddDialogue() {
            if (addDialog == null) {
                addDialog = new DialogAddElem(View.getSingleton().getOptionsDialog(null));
                addDialog.pack();
            }
            addDialog.setElems(model.getElements());
            addDialog.setVisible(true);
            
            AjaxSpiderParamElem elem = addDialog.getElem();
            addDialog.clear();
            
            return elem;
        }
        
        @Override
        public AjaxSpiderParamElem showModifyDialogue(AjaxSpiderParamElem e) {
            if (modifyDialog == null) {
                modifyDialog = new DialogModifyElem(View.getSingleton().getOptionsDialog(null));
                modifyDialog.pack();
            }
            modifyDialog.setElems(model.getElements());
            modifyDialog.setElem(e);
            modifyDialog.setVisible(true);
            
            AjaxSpiderParamElem elem = modifyDialog.getElem();
            modifyDialog.clear();
            
            if (!elem.equals(e)) {
                return elem;
            }
            
            return null;
        }
        
        @Override
        public boolean showRemoveDialogue(AjaxSpiderParamElem e) {
            JCheckBox removeWithoutConfirmationCheckBox = new JCheckBox(REMOVE_DIALOG_CHECKBOX_LABEL);
            Object[] messages = {REMOVE_DIALOG_TEXT, " ", removeWithoutConfirmationCheckBox};
            int option = JOptionPane.showOptionDialog(View.getSingleton().getMainFrame(), messages, REMOVE_DIALOG_TITLE,
                    JOptionPane.OK_CANCEL_OPTION, JOptionPane.QUESTION_MESSAGE,
                    null, new String[] { REMOVE_DIALOG_CONFIRM_BUTTON_LABEL, REMOVE_DIALOG_CANCEL_BUTTON_LABEL }, null);

            if (option == JOptionPane.OK_OPTION) {
                setRemoveWithoutConfirmation(removeWithoutConfirmationCheckBox.isSelected());
                
                return true;
            }
            
            return false;
        }
	}
	
  }  //  @jve:decl-index=0:visual-constraint="10,10"