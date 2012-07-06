package org.zaproxy.zap.extension.spiderAjax;

import java.awt.CardLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.view.AbstractParamPanel;
import org.zaproxy.zap.utils.ZapPortNumberSpinner;
import org.zaproxy.zap.utils.ZapTextField;
import org.zaproxy.zap.view.LayoutHelper;
import com.crawljax.browser.EmbeddedBrowser.BrowserType;

public class OptionsAjaxSpider extends AbstractParamPanel {


	private static final long serialVersionUID = -1350537974139536669L;

	private ExtensionAjax extension=null;
	private JPanel panelLocalProxy = null;
	private JPanel panelProxy = null;  //  @jve:decl-index=0:visual-constraint="10,283"
	private ZapTextField txtProxyIp = null;
    
	// ZAP: Do not allow invalid port numbers
	private ZapPortNumberSpinner spinnerProxyPort = null;
	private JCheckBox ClickAllElems = null;
	private JCheckBox firefox = null;
	private JCheckBox chrome = null;
	private JCheckBox  ie = null;
	private JLabel jLabel6 = null;
    public OptionsAjaxSpider(ExtensionAjax extension) {
    	
        super();
    	this.extension=extension;

 		initialize();
   }
    
	/**
	 * This method initializes panelAjaxProxy
	 * 	
	 * @return javax.swing.JPanel	
	 */    
	private JPanel getPanelLocalProxy() {
		if (panelLocalProxy == null) {
			jLabel6 = new JLabel();
			GridBagConstraints gridBagConstraints15 = new GridBagConstraints();
			java.awt.GridBagConstraints gridBagConstraints7 = new GridBagConstraints();

			java.awt.GridBagConstraints gridBagConstraints6 = new GridBagConstraints();

			java.awt.GridBagConstraints gridBagConstraints5 = new GridBagConstraints();

			java.awt.GridBagConstraints gridBagConstraints4 = new GridBagConstraints();

			javax.swing.JLabel jLabel = new JLabel();

			javax.swing.JLabel jLabel1 = new JLabel();
			
			panelLocalProxy = new JPanel();
			panelLocalProxy.setLayout(new GridBagLayout());
			panelLocalProxy.setBorder(javax.swing.BorderFactory.createTitledBorder(
					null, this.extension.getString("ajax.proxy.local.title"), javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, 
					javax.swing.border.TitledBorder.DEFAULT_POSITION, new java.awt.Font("Dialog", java.awt.Font.PLAIN, 11), java.awt.Color.black));	// ZAP: i18n
			jLabel.setText("Address (eg localhost, 127.0.0.1)");
			gridBagConstraints4.gridx = 0;
			gridBagConstraints4.gridy = 0;
			gridBagConstraints4.ipadx = 0;
			gridBagConstraints4.ipady = 0;
			gridBagConstraints4.anchor = java.awt.GridBagConstraints.WEST;
			gridBagConstraints4.insets = new java.awt.Insets(2,2,2,2);
			gridBagConstraints4.weightx = 0.5D;
			gridBagConstraints4.fill = java.awt.GridBagConstraints.HORIZONTAL;
			gridBagConstraints5.gridx = 1;
			gridBagConstraints5.gridy = 0;
			gridBagConstraints5.weightx = 0.5D;
			gridBagConstraints5.fill = java.awt.GridBagConstraints.HORIZONTAL;
			gridBagConstraints5.ipadx = 50;
			gridBagConstraints5.ipady = 0;
			gridBagConstraints5.anchor = java.awt.GridBagConstraints.EAST;
			gridBagConstraints5.insets = new java.awt.Insets(2,2,2,2);
			gridBagConstraints6.gridx = 0;
			gridBagConstraints6.gridy = 1;
			gridBagConstraints6.ipadx = 0;
			gridBagConstraints6.ipady = 0;
			gridBagConstraints6.anchor = java.awt.GridBagConstraints.WEST;
			gridBagConstraints6.fill = java.awt.GridBagConstraints.HORIZONTAL;
			gridBagConstraints6.insets = new java.awt.Insets(2,2,2,2);
			gridBagConstraints6.weightx = 0.5D;
			gridBagConstraints7.gridx = 1;
			gridBagConstraints7.gridy = 1;
			gridBagConstraints7.weightx = 0.5D;
			gridBagConstraints7.fill = java.awt.GridBagConstraints.HORIZONTAL;
			gridBagConstraints7.ipadx = 50;
			gridBagConstraints7.ipady = 0;
			gridBagConstraints7.anchor = java.awt.GridBagConstraints.EAST;
			gridBagConstraints7.insets = new java.awt.Insets(2,2,2,2);
			jLabel1.setText(this.extension.getString("ajax.proxy.local.label.port"));
			jLabel6.setText(this.extension.getString("ajax.proxy.local.label.browser"));
			gridBagConstraints15.anchor = java.awt.GridBagConstraints.NORTHWEST;
			gridBagConstraints15.gridx = 0;
			gridBagConstraints15.gridy = 4;
			gridBagConstraints15.insets = new java.awt.Insets(2,2,2,2);
			gridBagConstraints15.weightx = 1.0D;
			gridBagConstraints15.fill = java.awt.GridBagConstraints.HORIZONTAL;
			gridBagConstraints15.gridwidth = 2;
			panelLocalProxy.add(jLabel, gridBagConstraints4);
			panelLocalProxy.add(getTxtProxyIp(), gridBagConstraints5);
			panelLocalProxy.add(jLabel1, gridBagConstraints6);
			panelLocalProxy.add(getSpinnerProxyPort(), gridBagConstraints7);
			panelLocalProxy.add(jLabel6, gridBagConstraints15);
		}
		return panelLocalProxy;
	}
	
	/**
	 * This method initializes panelAjaxProxy	
	 * 	
	 * @return javax.swing.JPanel	
	 */    
	private JPanel getPanelProxy() {
		if (panelProxy == null) {
			GridBagConstraints gridBagConstraints2 = new GridBagConstraints();
			panelProxy = new JPanel();
			java.awt.GridBagConstraints gridBagConstraints1 = new GridBagConstraints();

			java.awt.GridBagConstraints gridBagConstraints8 = new GridBagConstraints();

			java.awt.GridBagConstraints gridBagConstraints9 = new GridBagConstraints();

			java.awt.GridBagConstraints gridBagConstraints10 = new GridBagConstraints();

			javax.swing.JLabel jLabel4 = new JLabel();
			javax.swing.JLabel jLabel5 = new JLabel();

			java.awt.GridBagConstraints gridBagConstraints14 = new GridBagConstraints();

			GridBagConstraints gridBagConstraints91 = new GridBagConstraints();

			java.awt.GridBagConstraints gridBagConstraints81 = new GridBagConstraints();

			panelProxy.setLayout(new GridBagLayout());

			gridBagConstraints8.gridx = 0;
			gridBagConstraints8.gridy = 0;
			gridBagConstraints8.insets = new java.awt.Insets(2,0,2,0);
			gridBagConstraints8.anchor = java.awt.GridBagConstraints.NORTHWEST;
			gridBagConstraints8.fill = java.awt.GridBagConstraints.HORIZONTAL;
			gridBagConstraints8.weightx = 1.0D;
			gridBagConstraints9.gridx = 0;
			gridBagConstraints9.gridy = 1;
			gridBagConstraints9.weightx = 1.0;
			gridBagConstraints9.fill = java.awt.GridBagConstraints.HORIZONTAL;
			gridBagConstraints9.insets = new java.awt.Insets(2,0,2,0);
			gridBagConstraints9.anchor = java.awt.GridBagConstraints.NORTHWEST;
			gridBagConstraints10.gridx = 0;
			gridBagConstraints10.gridy = 2;
			gridBagConstraints10.insets = new java.awt.Insets(2,0,2,0);
			gridBagConstraints10.anchor = java.awt.GridBagConstraints.NORTHWEST;
			gridBagConstraints10.fill = java.awt.GridBagConstraints.HORIZONTAL;
			gridBagConstraints1.weightx = 1.0;
			gridBagConstraints1.fill = java.awt.GridBagConstraints.HORIZONTAL;
			panelProxy.setName(Constant.messages.getString("options.proxy.local.label.local"));
		    if (Model.getSingleton().getOptionsParam().getViewParam().getWmUiHandlingOption() == 0) {
		    	panelProxy.setSize(303, 177);
		    }
			panelProxy.setFont(new java.awt.Font("Dialog", java.awt.Font.PLAIN, 11));
			gridBagConstraints81.gridx = 0;
			gridBagConstraints81.gridy = 0;
			gridBagConstraints81.ipadx = 2;
			gridBagConstraints81.ipady = 4;
			gridBagConstraints81.insets = new java.awt.Insets(2,2,2,2);
			gridBagConstraints81.anchor = java.awt.GridBagConstraints.NORTHWEST;
			gridBagConstraints81.fill = java.awt.GridBagConstraints.HORIZONTAL;
			gridBagConstraints81.weightx = 1.0D;
			gridBagConstraints81.weighty = 0.0D;
			gridBagConstraints91.gridx = 0;
			gridBagConstraints91.gridy = 2;
			gridBagConstraints91.anchor = java.awt.GridBagConstraints.NORTHWEST;
			gridBagConstraints91.fill = java.awt.GridBagConstraints.HORIZONTAL;
			gridBagConstraints91.weightx = 1.0D;
			gridBagConstraints91.weighty = 0.0D;
			gridBagConstraints91.ipady = 4;
			gridBagConstraints91.ipadx = 2;
			jLabel4.setText("");
			gridBagConstraints14.fill = java.awt.GridBagConstraints.BOTH;
			gridBagConstraints14.gridx = 0;
			gridBagConstraints14.gridy = 2;
			gridBagConstraints14.weightx = 1.0D;
			gridBagConstraints14.weighty = 1.0D;
			gridBagConstraints2.gridx = 0;
			gridBagConstraints2.gridy = 1;
			gridBagConstraints2.anchor = java.awt.GridBagConstraints.NORTHWEST;
			gridBagConstraints2.fill = java.awt.GridBagConstraints.HORIZONTAL;
			gridBagConstraints2.insets = new java.awt.Insets(2,2,2,2);
			gridBagConstraints2.weightx = 1.0D;
			panelProxy.add(getPanelLocalProxy(), gridBagConstraints81);
			panelProxy.add(jLabel4, gridBagConstraints14);
			panelProxy.add(getClickAllElems(), LayoutHelper.getGBC(0, 2, 3,  1.0D, 0, GridBagConstraints.HORIZONTAL, new Insets(2,2,2,2)));
			jLabel5.setText(this.extension.getString("ajax.proxy.local.label.browsers"));
			panelProxy.add(jLabel5, LayoutHelper.getGBC(0, 3, 3,  1.0D, 0, GridBagConstraints.HORIZONTAL, new Insets(2,2,2,2)));
			panelProxy.add(getFirefox(), LayoutHelper.getGBC(0, 4, 3,  1.0D, 1, GridBagConstraints.HORIZONTAL, new Insets(2,2,2,2)));
			panelProxy.add(getChrome(), LayoutHelper.getGBC(0, 4, 4,  2.0D, 2, GridBagConstraints.HORIZONTAL+2, new Insets(25,2,2,2)));
			panelProxy.add(getIE(), LayoutHelper.getGBC(0, 4, 4,  2.0D, 2, GridBagConstraints.HORIZONTAL+2, new Insets(50,2,2,2)));

		}
		return panelProxy;
	}

	/**
	 * This method initializes txtProxyIp	
	 * 	
	 * @return org.zaproxy.zap.utils.ZapTextField	
	 */    
	private ZapTextField getTxtProxyIp() {
		if (txtProxyIp == null) {
			txtProxyIp = new ZapTextField("");
		}
		return txtProxyIp;
	}


	
	/**
	 * This method initializes spinnerProxyPort	
	 * 	
	 * @return ZapPortNumberSpinner
	 */    
	private ZapPortNumberSpinner getSpinnerProxyPort() {
		if (spinnerProxyPort == null) {
			// ZAP: Do not allow invalid port numbers
			spinnerProxyPort = new ZapPortNumberSpinner(8081);
		}
		return spinnerProxyPort;
	}
	
	/**
	 * This method initializes this
	 * 
	 * @return void
	 */
	private void initialize() {
        this.setLayout(new CardLayout());
        this.setName(this.extension.getString("ajax.proxy.local.title"));
	    if (Model.getSingleton().getOptionsParam().getViewParam().getWmUiHandlingOption() == 0) {
	    	this.setSize(391, 320);
	    }
        this.add(getPanelProxy(), getPanelProxy().getName()); 
	}
	
	@Override
	public void initParam(Object obj) {
	    
	    // set Local Proxy parameters
	    txtProxyIp.setText(this.extension.getProxy().getProxyHost());
	    txtProxyIp.discardAllEdits();
	    spinnerProxyPort.setValue(this.extension.getProxy().getProxyPort());
	    
	    //set the browser type
	    if(this.extension.getProxy().getBrowser() == BrowserType.firefox){
	    	this.getFirefox().setSelected(true);
		    this.getChrome().setSelected(false);
	    } else if (this.extension.getProxy().getBrowser() == BrowserType.chrome){
		    this.getChrome().setSelected(true);
	    	this.getFirefox().setSelected(false);
	    }
	}
	
	@Override
	public void validateParam(Object obj) throws Exception {
		
		//if both or none are selected we use firefox
		if(getFirefox().isSelected() && getChrome().isSelected() && getIE().isSelected()){
			getChrome().setSelected(false);
			getIE().setSelected(false);
			getFirefox().setSelected(true);
		} else if(!getFirefox().isSelected() && !getChrome().isSelected()&& !getIE().isSelected()){
			getChrome().setSelected(false);
			getIE().setSelected(false);
			getFirefox().setSelected(true);	
		}
	}

	
	@Override
	public void saveParam(Object obj) throws Exception  {; 
	    this.extension.getProxy().setMegaScan(getClickAllElems().isSelected());
		this.extension.getProxy().setProxyHost(txtProxyIp.getText());
		this.extension.getProxy().setProxyPort(spinnerProxyPort.getValue());
		if(getFirefox().isSelected()){
			this.extension.getProxy().setBrowser(BrowserType.firefox);
		}
		if(getChrome().isSelected()){
			this.extension.getProxy().setBrowser(BrowserType.chrome);
		}
		if(getIE().isSelected()){
			this.extension.getProxy().setBrowser(BrowserType.ie);
		}
	}



	private JCheckBox getClickAllElems() {
			if (ClickAllElems == null) {
				ClickAllElems = new JCheckBox();
				ClickAllElems.setText(this.extension.getString("ajax.proxy.local.label.allElems"));
			}
			return ClickAllElems;
		}

	private JCheckBox getFirefox() {
		if (firefox == null) {
			firefox = new JCheckBox();
			firefox.setText(this.extension.getString("ajax.proxy.local.label.firefox"));
		}
		return firefox;
	}
	private JCheckBox getChrome() {
		if (chrome == null) {
			chrome = new JCheckBox();
			chrome.setText(this.extension.getString("ajax.proxy.local.label.chrome"));
		}
		return chrome;
	}
	private JCheckBox getIE() {
		if (ie == null) {
			ie = new JCheckBox();
			ie.setText(this.extension.getString("ajax.proxy.local.label.ie"));
		}
		return ie;
	}
	
	

	@Override
	public String getHelpIndex() {
		// ZAP: added help index
		return "ui.dialogs.options.localproxy";
	}
	
  }  //  @jve:decl-index=0:visual-constraint="10,10"