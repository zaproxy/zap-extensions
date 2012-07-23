/*
 *
 * Paros and its related class files.
 * 
 * Paros is an HTTP/HTTPS proxy for assessing web application security.
 * Copyright (C) 2003-2004 Chinotec Technologies Company
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the Clarified Artistic License
 * as published by the Free Software Foundation.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * Clarified Artistic License for more details.
 * 
 * You should have received a copy of the Clarified Artistic License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */
// ZAP: 2012/04/14 Changed the method initParam to discard all edits.
// ZAP: 2012/04/25 Added @Override annotation to all appropriate methods.

package org.zaproxy.zap.extension.report;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.util.ResourceBundle;

import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.filechooser.FileFilter;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.view.AbstractParamPanel;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.utils.ZapTextArea;
import org.zaproxy.zap.utils.ZapTextField;


public class OptionsReportExportPanel extends AbstractParamPanel {
	// ZAP: i18n	
	private static final long serialVersionUID = 1L;
	private JPanel editPane = null;
	private ZapTextField editTitleReport = null;
	private ZapTextField editLogoFileName = null;
	private ZapTextField editWorkingDir = null;
	private ZapTextField editCustomerName= null;
	private ZapTextArea editConfidentialText= null;
	private ZapTextField editCompanyName = null;
	private ZapTextField editPDFKeywords = null;
	private ZapTextField editAuthorName= null;
	private JButton chooseApp = null;
	private JButton chooseDir = null;
	private ResourceBundle messages = null;
	private JComboBox<String> comboLevel = null;
	
    public OptionsReportExportPanel() {
        super();
 		initialize();
   }
    
    private JComboBox<String> getComboLevel() {
		if (comboLevel == null) {
			comboLevel = new JComboBox<String>();
			comboLevel.addItem("PDF");
			comboLevel.addItem("ODT");
			comboLevel.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent e) {
					// Set the explanation
				    if (comboLevel.getSelectedItem().equals("ODT")){
				    	View.getSingleton().showMessageDialog("Coming Soon!!");
				    	comboLevel.setSelectedIndex(0);
				    } 
				}});
		}
		return comboLevel;
	}


    public String getMessageString(String key) {
		return messages.getString(key);
	}

    
	public ZapTextField getEditTitleReport() {
		return editTitleReport;
	}

	public void setEditTitleReport(ZapTextField editTitleReport) {
		this.editTitleReport = editTitleReport;
	}

	public ZapTextField getEditLogoFileName() {
		return editLogoFileName;
	}

	public void setEditLogoFileName(ZapTextField editLogoFileName) {
		this.editLogoFileName = editLogoFileName;
	}

	public ZapTextField getEditWorkingDir() {
		return editWorkingDir;
	}

	public void setEditWorkingDir(ZapTextField editWorkingDir) {
		this.editWorkingDir = editWorkingDir;
	}

	public ZapTextField getEditCustomerName() {
		return editCustomerName;
	}

	public void setEditCustomerName(ZapTextField editCustomerName) {
		this.editCustomerName = editCustomerName;
	}

	public ZapTextArea getEditConfidentialText() {
		return editConfidentialText;
	}

	public void setEditConfidentialText(ZapTextArea editConfidentialText) {
		this.editConfidentialText = editConfidentialText;
	}

	public ZapTextField getEditCompanyName() {
		return editCompanyName;
	}

	public void setEditCompanyName(ZapTextField editCompanyName) {
		this.editCompanyName = editCompanyName;
	}

	public ZapTextField getEditPDFKeywords() {
		return editPDFKeywords;
	}

	public void setEditPDFKeywords(ZapTextField editPDFKeywords) {
		this.editPDFKeywords = editPDFKeywords;
	}

	public ZapTextField getEditAuthorName() {
		return editAuthorName;
	}

	public void setEditAuthorName(ZapTextField editAuthorName) {
		this.editAuthorName = editAuthorName;
	}

	/**
	 * This method initializes this
	 * 
	 * @return void
	 */
	private void initialize() {

		// Load extension specific language files - these are held in the extension jar
        messages = ResourceBundle.getBundle(
        		this.getClass().getPackage().getName() + ".Messages", Constant.getLocale());
        
        getComboLevel();
        
        GridBagConstraints gbc1 = new GridBagConstraints();
        GridBagConstraints gbc2 = new GridBagConstraints();
        GridBagConstraints gbc3 = new GridBagConstraints();
        GridBagConstraints gbc4 = new GridBagConstraints();

        JLabel jLabel1 = new JLabel();
      //  JLabel jLabel2 = new JLabel();

        this.setLayout(new GridBagLayout());
        if (Model.getSingleton().getOptionsParam().getViewParam().getWmUiHandlingOption() == 0) {
        	this.setSize(409, 268);
        }
        this.setName(getMessageString("alert.export.message.export.option.title"));
        
        jLabel1.setText(getMessageString("alert.export.message.export.option.desc"));
        jLabel1.setPreferredSize(new java.awt.Dimension(494,30));
        jLabel1.setMinimumSize(new java.awt.Dimension(494,30));

        gbc1.gridx = 0;
        gbc1.gridy = 0;
        gbc1.gridheight = 1;
        gbc1.ipady = 5;
        gbc1.insets = new java.awt.Insets(10,0,5,0);
        gbc1.anchor = GridBagConstraints.NORTHWEST;
        gbc1.fill = GridBagConstraints.HORIZONTAL;
        
        gbc2.gridx = 0;
        gbc2.gridy = 1;
        gbc2.weightx = 1.0;
        gbc2.weighty = 1.0;
        gbc2.fill = GridBagConstraints.BOTH;
        gbc2.ipadx = 0;
        gbc2.insets = new java.awt.Insets(0,0,0,0);
        gbc2.anchor = GridBagConstraints.NORTHWEST;
        
        gbc3.gridx = 0;
        gbc3.gridy = 2;
        gbc3.weightx = 1.0;
        //gbc3.weighty = 1.0;
        gbc3.fill = GridBagConstraints.BOTH;
        gbc3.ipadx = 0;
        gbc3.insets = new java.awt.Insets(0,0,0,0);
        gbc3.anchor = GridBagConstraints.NORTHWEST;
        
        gbc4.gridx = 0;
        gbc4.gridy = 3;
        gbc4.weightx = 1.0;
        gbc4.weighty = 0.2;
        gbc4.fill = GridBagConstraints.BOTH;
        gbc4.ipadx = 0;
        gbc4.insets = new java.awt.Insets(0,0,0,0);
        gbc4.anchor = GridBagConstraints.NORTHWEST;
        
        this.add(jLabel1, gbc1);
       // this.add(getJScrollPane(), gbc2);
        this.add(getEditPane(), gbc3);
       // this.add(jLabel2, gbc4);
			
	}
	
	private GridBagConstraints getGridBackConstrants(int y, int x, double weight, boolean fullWidth) {
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridy = y;
        gbc.gridx = x;
        gbc.insets = new java.awt.Insets(0,0,0,0);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
		gbc.weightx = weight;
		if (fullWidth) {
			gbc.gridwidth = 2;
		}
		return gbc;
	}
	

	
	private JPanel getEditPane() {
		if (editPane == null) {
			editPane = new JPanel();
			editPane.setBorder(
					javax.swing.BorderFactory.createTitledBorder(
							null, "", 
							javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, 
							javax.swing.border.TitledBorder.DEFAULT_POSITION, 
							new java.awt.Font("Dialog", java.awt.Font.PLAIN, 11), 
							java.awt.Color.black));
			editPane.setFont(new java.awt.Font("Dialog", java.awt.Font.PLAIN, 11));
			editPane.setLayout(new GridBagLayout());
			
	        editTitleReport = new ZapTextField();
	        editLogoFileName = new ZapTextField();
	        editLogoFileName.setEditable(false);
	        editWorkingDir = new ZapTextField();
	        editWorkingDir.setEditable(false);
	        
	        chooseApp = new JButton(getMessageString("alert.export.message.export.option.label.file")); 
			chooseApp.addActionListener(new java.awt.event.ActionListener() { 
				@Override
				public void actionPerformed(java.awt.event.ActionEvent e) {    
			    	JFileChooser fcCommand = new JFileChooser();
					fcCommand.setFileFilter( new FileFilter()
					{
						@Override
						public String getDescription() {
							return getMessageString("alert.export.message.export.option.title");
						}
						@Override
						public boolean accept(File f) {
							return f.isDirectory() || f.canExecute() ;
						}
					} );
					if (editLogoFileName.getText() != null && editLogoFileName.getText().length() > 0) {
						// If theres and existing file select containing directory 
						File f = new File(editLogoFileName.getText());
						fcCommand.setCurrentDirectory(f.getParentFile());
					}
					
					int state = fcCommand.showOpenDialog( null );

					if ( state == JFileChooser.APPROVE_OPTION )
					{
						editLogoFileName.setText(fcCommand.getSelectedFile().toString() );
					}
				}
			});

	        chooseDir = new JButton(getMessageString("alert.export.message.export.option.label.dir")); 
			chooseDir.addActionListener(new java.awt.event.ActionListener() { 
				@Override
				public void actionPerformed(java.awt.event.ActionEvent e) {    
			    	JFileChooser fcDirectory = new JFileChooser();
			    	fcDirectory.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
			    	 // disable the "All files" option.
			    	fcDirectory.setAcceptAllFileFilterUsed(false);
			    	
					if (editWorkingDir.getText() != null && editWorkingDir.getText().length() > 0) {
						// If theres and existing directory then select it 
						File f = new File(editWorkingDir.getText());
						fcDirectory.setCurrentDirectory(f);
					}
					
					int state = fcDirectory.showOpenDialog( null );

					if ( state == JFileChooser.APPROVE_OPTION )
					{
						editWorkingDir.setText(fcDirectory.getSelectedFile().toString() );
					}
				}
			});

	        editCustomerName = new ZapTextField();
	        
	        editConfidentialText = new ZapTextArea();
	        editConfidentialText.setLineWrap(true);
	        editConfidentialText.setRows(3);
	        editConfidentialText.setFont(new java.awt.Font("Dialog", java.awt.Font.PLAIN, 11));
	        
	        editCompanyName = new ZapTextField();
	        editPDFKeywords = new ZapTextField();
	        editAuthorName = new ZapTextField();
	        
	    	
	    	int rowId = 0;
	    	
   
			editPane.add(new JLabel(getMessageString("alert.export.message.export.option.format")), 
	        		getGridBackConstrants(rowId, 0, 0, false));
	        editPane.add(getComboLevel(), getGridBackConstrants(rowId++, 1, 1, true));
			
	        editPane.add(new JLabel(getMessageString("alert.export.message.export.pdf.title")), 
	        		getGridBackConstrants(rowId, 0, 0, false));
	        editPane.add(editTitleReport, getGridBackConstrants(rowId++, 1, 1, true));
	        
	        editPane.add(new JLabel(getMessageString("alert.export.message.export.option.companyname")), 
	        		getGridBackConstrants(rowId, 0, 0, false));
	        editPane.add(editCompanyName, getGridBackConstrants(rowId++, 1, 1, true));
	        
	        editPane.add(new JLabel(getMessageString("alert.export.message.export.option.logofilename")), 
	        		getGridBackConstrants(rowId, 0, 0, false));
	        editPane.add(editLogoFileName, getGridBackConstrants(rowId++, 1, 1, false));
	        editPane.add(chooseApp, getGridBackConstrants(rowId-1, 2, 0, false));
	        
	        editPane.add(new JLabel(getMessageString("alert.export.message.export.option.imagesdir")), 
	        		getGridBackConstrants(rowId, 0, 0, false));
	        editPane.add(editWorkingDir, getGridBackConstrants(rowId++, 1, 1, false));
	        editPane.add(chooseDir, getGridBackConstrants(rowId-1, 2, 0, false));
	        
	        editPane.add(new JLabel(getMessageString("alert.export.message.export.pdf.customername")), 
	        		getGridBackConstrants(rowId, 0, 0, false));
	        editPane.add(editCustomerName, getGridBackConstrants(rowId++, 1, 1, true));
	        
	        editPane.add(new JLabel(getMessageString("alert.export.message.export.pdf.confidential")), 
	        		getGridBackConstrants(rowId, 0, 0, false));
	        editPane.add(editConfidentialText, getGridBackConstrants(rowId++, 1, 1, true));
	        
	        editPane.add(new JLabel(getMessageString("alert.export.message.export.option.authorname")), 
	        		getGridBackConstrants(rowId, 0, 0, false));
	        editPane.add(editAuthorName, getGridBackConstrants(rowId++, 1, 1, true));
	        
	        editPane.add(new JLabel(getMessageString("alert.export.message.export.option.pdfkeywords")), 
	        		getGridBackConstrants(rowId, 0, 0, false));
	        editPane.add(editPDFKeywords, getGridBackConstrants(rowId++, 1, 1, true));
	        
	        
	        
	        
	        
		}
		return editPane;
	}

    @Override
    public void validateParam(Object obj) throws Exception {
    	
    }
    
    @Override
    public void saveParam(Object obj) throws Exception {
    	OptionsParam options = (OptionsParam) obj;
		
		ReportExportParam param = (ReportExportParam) options.getParamSet(ReportExportParam.class);
		if (param!=null){
			param.setTitleReport(getEditTitleReport().getText());
			param.setLogoFileName(getEditLogoFileName().getText());
			param.setWorkingDirImages(getEditWorkingDir().getText());
			param.setCustomerName(getEditCustomerName().getText());
			param.setConfidentialText(getEditConfidentialText().getText());
			param.setPdfKeywords(getEditPDFKeywords().getText());
			param.setAuthorName(getEditAuthorName().getText());
			param.setCompanyName(getEditCompanyName().getText());
			param.setFormatReport(getComboLevel().getSelectedItem().toString());

		}
    }

	@Override
	public String getHelpIndex() {
		return null;
	}

	@Override
	public void initParam(Object obj) {
		OptionsParam options = (OptionsParam) obj;
		
		ReportExportParam param = (ReportExportParam) options.getParamSet(ReportExportParam.class);
		if (param!=null){
			getEditTitleReport().setText(param.getTitleReport());
			getEditLogoFileName().setText(param.getLogoFileName());
			getEditWorkingDir().setText(param.getWorkingDirImages());
			getEditCustomerName().setText(param.getCustomerName());
			getEditConfidentialText().setText(param.getConfidentialText());
			getEditPDFKeywords().setText(param.getPdfKeywords());
			getEditAuthorName().setText(param.getAuthorName());
			getEditCompanyName().setText(param.getCompanyName());
			getComboLevel().setSelectedIndex(0);
		}
		
	
	}

}  
