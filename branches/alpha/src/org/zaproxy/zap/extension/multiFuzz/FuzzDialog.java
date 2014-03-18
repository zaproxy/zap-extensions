/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 * 
 * Copyright 2010 psiinon@gmail.com
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
package org.zaproxy.zap.extension.multiFuzz;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.Graphics;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.HeadlessException;
import java.awt.Rectangle;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.text.NumberFormat;
import java.util.ArrayList;
import java.util.List;

import javax.swing.AbstractAction;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFormattedTextField;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;

import org.apache.log4j.Logger;
import org.owasp.jbrofuzz.core.NoSuchFuzzerException;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.AbstractDialog;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.multiFuzz.MFuzzableMessage;

public abstract class FuzzDialog extends AbstractDialog {

    private static final long serialVersionUID = 3855005636913607013L;
    private static final Logger logger = Logger.getLogger(FuzzDialog.class);
    
    private MultiExtensionFuzz extension;
	protected FuzzerHandler handler;
	protected MFuzzableMessage fuzzableMessage;
	
	private ArrayList<FuzzGap> gaps = new ArrayList<FuzzGap>();
	private int currentIndex = 0;
	private boolean adding = false;
	private boolean changeable = true;
	
	private JSplitPane splitPane;
	private MFuzzableComponent messageContent;
	private JLabel info = new JLabel();
	private ColorLine colors = new ColorLine();
	private JFormattedTextField gapNrField;
	private DefaultComboBoxModel<String> fuzzerModel = null;
    private JComboBox<String> categoryField = null;
    private JList<String> fuzzersField = null;
    
    private JButton cancelButton = null;
    private JButton startButton = null;
	private JButton prevButton;
	private JButton nextButton;
	private JButton addComponentButton;
	private JButton delComponentButton;

    public FuzzDialog(MultiExtensionFuzz extension, MFuzzableComponent fuzzableComponent) throws HeadlessException {
        super(View.getSingleton().getMainFrame(), true);
        
        this.setTitle(extension.getMessageString("fuzz.title"));
        
        this.extension = extension;
        this.messageContent = fuzzableComponent;
        fuzzableMessage = fuzzableComponent.getFuzzableMessage();
		initialize();
		FuzzGap fuzzGap = new FuzzGap(fuzzableComponent.currentSelection(), fuzzableMessage);
		addComponent(fuzzGap);
		getDelComponentButton().setEnabled(false);
    }
    
	/**
	 * This method initializes this
	 */
	protected void initialize() {
        this.setContentPane(getJTabbed());
        setDefaultCategory();
		this.setSize(800, 400);
	}

	private JSplitPane getJTabbed() {
		if (splitPane == null) {
			splitPane = new JSplitPane();
			JPanel panel = new JPanel();
			panel.setLayout(new GridBagLayout());
			int currentRow = 0;
			Font headLine = new Font(Font.SERIF,Font.BOLD, 16);  
			JLabel headL = new JLabel(extension.getMessageString("fuzz.title"));
			headL.setFont(headLine);
			panel.add(headL, getGBC(0, currentRow, 3, 0.25));
			panel.add(getPrevButton(), getGBC(3, currentRow, 1, 0.083));
			panel.add(getGapNrField(), getGBC(4, currentRow, 1, 0.083));
			panel.add(getNextButton(), getGBC(5, currentRow, 1, 0.083));
			currentRow++;
			panel.add(colors, getGBC(0, currentRow, 6, 0.25));
			currentRow++;
			currentRow = addCustomComponents(panel, currentRow);

			panel.add(getCategoryField(), getGBC(0, currentRow, 6, 0.25D));
			currentRow++;

			getFuzzersField().addListSelectionListener(new ListSelectionListener() {
				@Override
				public void valueChanged(ListSelectionEvent e2) {
					if(changeable){
						changeable = false;
						ArrayList<Integer> indices = gaps.get(currentIndex).getIndices();
						indices.clear();
						indices.add(getCategoryField().getSelectedIndex());
						for(int i : getFuzzersField().getSelectedIndices()){
							indices.add(i);
						}
						getStartButton().setEnabled(check());
						changeable = true;
					}
				}
			});
			panel.add(new JScrollPane(getFuzzersField()), getGBC(0, currentRow, 6, 1.0D, 0.25D));
			currentRow++;

			panel.add(getAddComponentButton(), getGBC(0, currentRow, 3, 0.125, java.awt.GridBagConstraints.NONE));
			panel.add(getDelComponentButton(), getGBC(3, currentRow, 3, 0.125, java.awt.GridBagConstraints.NONE));
			currentRow++;

			panel.add(getStartButton(), getGBC(0, currentRow, 3, 0.25, java.awt.GridBagConstraints.NONE));
			panel.add(getCancelButton(), getGBC(3, currentRow, 3, 0.25, java.awt.GridBagConstraints.NONE));

			Dimension minimumSize = new Dimension(50, 50);
			panel.setMinimumSize(minimumSize);
			getMessageContent().underlyingComponent().setMinimumSize(minimumSize);
			splitPane.setOrientation(JSplitPane.HORIZONTAL_SPLIT);
			splitPane.setLeftComponent(getMessageContent().underlyingComponent());
			splitPane.setRightComponent(panel);
			splitPane.setDividerLocation(0.5);
			splitPane.setDividerLocation(0.5);
		}
		return splitPane;
	}
    
    protected abstract int addCustomComponents(JPanel panel, int row);

    protected GridBagConstraints getGBC(int x, int y, int width, double weightx) {
        return this.getGBC(x, y, width, weightx, 0.0);
    }
    protected GridBagConstraints getGBC(int x, int y, int width, double weightx, double weighty) {
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = x;
        gbc.gridy = y;
        gbc.insets = new java.awt.Insets(1,5,1,5);
        gbc.anchor = java.awt.GridBagConstraints.NORTHWEST;
        gbc.fill = java.awt.GridBagConstraints.BOTH;
        gbc.weightx = weightx;
        gbc.weighty = weighty;
        gbc.gridwidth = width;
        return gbc;
    }
    protected GridBagConstraints getGBC(int x, int y, int width, double weightx, int fill) {
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = x;
        gbc.gridy = y;
        gbc.insets = new java.awt.Insets(1,5,1,5);
        gbc.anchor = java.awt.GridBagConstraints.NORTHWEST;
        gbc.fill = fill;
        gbc.weightx = weightx;
        gbc.weighty = 0.0;
        gbc.gridwidth = width;
        return gbc;
    }

	private MFuzzableComponent getMessageContent(){
		ArrayList<FuzzLocation> fl = new ArrayList<FuzzLocation>();
		for(FuzzGap g : gaps){
			fl.add(g.getFuzzLoc());
		}
		messageContent.highLight(fl, currentIndex);
		colors.repaint();
		return messageContent;
	}
	private void setFuzzerNames () {
		fuzzerModel.removeAllElements();
		
		String category = (String) getCategoryField().getSelectedItem();
		if (category == null) {
			return;
		}
		
		if (isCustomCategory()) {
			List<String> fuzzers = extension.getCustomFileList();
			for (String fuzzer : fuzzers) {
				fuzzerModel.addElement(fuzzer);
			}
		} else if (isJBroFuzzCategory()) {
			for (String fuzzer : extension.getJBroFuzzFuzzerNames(category)) {
				fuzzerModel.addElement(fuzzer);
			}
		} else {
			List<String> fuzzers = extension.getFileFuzzerNames(category);
			for (String fuzzer : fuzzers) {
				fuzzerModel.addElement(fuzzer);
			}
		}
	}	
    protected JList<String> getFuzzersField() {
		if (fuzzersField == null) {
			fuzzerModel = new DefaultComboBoxModel<>();
			fuzzersField = new JList<>();
			fuzzersField.setModel(fuzzerModel);
			setFuzzerNames();
		}
		return fuzzersField;
	}
	private JComboBox<String> getCategoryField() {
		if (categoryField == null) {
			categoryField = new JComboBox<>();

			// Add File based fuzzers (fuzzdb)
			for (String category : extension.getFileFuzzerCategories()) {
				categoryField.addItem(category);
			}
			
			// Add jbrofuzz fuzzers
			for (String category : extension.getJBroFuzzCategories()) {
				categoryField.addItem(category);
			}

			// Custom category
			categoryField.addItem(extension.getMessageString("fuzz.category.custom"));
			
			categoryField.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent e) {
					setFuzzerNames();
				}});
		}
		return categoryField;
	}
	private JButton getAddComponentButton(){
		if (addComponentButton == null) {
			addComponentButton = new JButton();
			addComponentButton.setAction(getAddFuzzAction());
		}
		addComponentButton.setEnabled(true);
		return addComponentButton;
	}
	private JButton getDelComponentButton(){
		if (delComponentButton == null) {
			delComponentButton = new JButton();
			delComponentButton.setAction(getDelFuzzAction());
		}
		delComponentButton.setEnabled(true);
		return delComponentButton;
	}
	private JButton getNextButton(){
		if (nextButton == null) {
			nextButton = new JButton();
			nextButton.setAction(new AbstractAction(){
				@Override
				public void actionPerformed(ActionEvent e) {
					setSelection(currentIndex + 1);
					ArrayList<FuzzLocation> fl = new ArrayList<FuzzLocation>();
					for(FuzzGap g : gaps){
						fl.add(g.getFuzzLoc());
					}
					messageContent.highLight(fl, currentIndex);
					colors.repaint();
				}
			});
			nextButton.setText(">");
		}
		nextButton.setEnabled(true);
		return nextButton;
	}
	private JButton getPrevButton(){
		if (prevButton == null) {
			prevButton = new JButton();
			prevButton.setAction(new AbstractAction(){
				@Override
				public void actionPerformed(ActionEvent e) {
					setSelection(currentIndex - 1);
					ArrayList<FuzzLocation> fl = new ArrayList<FuzzLocation>();
					for(FuzzGap g : gaps){
						fl.add(g.getFuzzLoc());
					}
					messageContent.highLight(fl, currentIndex);
					colors.repaint();
				}
			});
			prevButton.setText("<");
		}
		prevButton.setEnabled(true);
		return prevButton;
	}
    protected JButton getStartButton() {
        if (startButton == null) {
            startButton = new JButton();
            startButton.setAction(getStartFuzzAction());
        }
        return startButton;
    }
	protected JButton getCancelButton() {
		if (cancelButton == null) {
			cancelButton = new JButton();
			cancelButton.setAction(getCancelFuzzAction());
		}
		return cancelButton;
	}
	private JFormattedTextField getGapNrField(){
		if(gapNrField == null){
			gapNrField = new JFormattedTextField(NumberFormat.getNumberInstance());
			gapNrField.setValue(new Integer(1));
			gapNrField.setColumns(2);
			gapNrField.addPropertyChangeListener("value", new PropertyChangeListener() {
				@Override
				public void propertyChange(PropertyChangeEvent arg0) {
					if(arg0.getSource() == gapNrField){
						setSelection(((Number)gapNrField.getValue()).intValue() - 1);
					}
				}
			});
		}
		return gapNrField;
	}
	private Color getColor(int n) {
		float hue = (float) (n % 5) / 5;
		float sat = (float) Math.ceil((float)n/5)/2;
		float bright = (float) Math.ceil((float)n/5);
		return Color.getHSBColor(hue, sat, bright);
	}
    
	protected abstract FuzzProcessFactory getFuzzProcessFactory();
	public boolean addComponent(FuzzGap gap) {
		if(isValidInterval(gap.getFuzzLoc())){
			gaps.add(gap);
			ArrayList<FuzzLocation> fl = new ArrayList<FuzzLocation>();
			for(FuzzGap g : gaps){
				fl.add(g.getFuzzLoc());
			}
			messageContent.highLight(fl, currentIndex);
			colors.repaint();
			return true;
		}
		else{
			return false;
		}
	}
	private boolean isValidInterval(FuzzLocation FuzzLoc){
		boolean valid = true;
		for(FuzzGap g : gaps){
			valid = FuzzLoc.overLap(g.getFuzzLoc());
		}
		return valid;
	}
	private void setSelection(int index){
		if(changeable){
			changeable = false;
			currentIndex = (index + gaps.size()) % gaps.size();
			getGapNrField().setText(""+(currentIndex + 1));
			ArrayList<Integer> indices = gaps.get(currentIndex).getIndices();
			if(indices.size() > 1){ 
				getCategoryField().setSelectedIndex(indices.get(0));
				int[] pos = new int[indices.size() - 1];
				for(int i = 1; i < indices.size(); i++){
					pos[i - 1] = indices.get(i);
				}
				getFuzzersField().setSelectedIndices(pos);
			}
			else{
				getCategoryField().setSelectedIndex(0);
				getFuzzersField().setSelectedIndex(0);
			}
			ArrayList<FuzzLocation> fl = new ArrayList<FuzzLocation>();
			for(FuzzGap g : gaps){
				fl.add(g.getFuzzLoc());
			}
			messageContent.highLight(fl, currentIndex);
			colors.repaint();
			changeable = true;
		}
	}
    protected MultiExtensionFuzz getExtension(){
    	return this.extension;
    } 
	private boolean check(){
		//check if every gap has some chosen Fuzzer
		boolean check = gaps.size() > 0;
		for(int i = 0; i < gaps.size(); i++){
			check = check && check(i);
		}
		return check;
	}
	private boolean check(int index){
		ArrayList<Integer> indices = gaps.get(index).getIndices();
		return (indices.size() >= 2) && (indices.get(0) != 0) ;
	}
	
	protected AddFuzzAction getAddFuzzAction() {
		return new AddFuzzAction();
	}
	protected DelFuzzAction getDelFuzzAction() {
		return new DelFuzzAction();
	}
	protected StartFuzzAction getStartFuzzAction() {
	    return new StartFuzzAction();
	}
    protected CancelFuzzAction getCancelFuzzAction() {
        return new CancelFuzzAction();
    }
	
	private boolean isCustomCategory() {
		return extension.getMessageString("fuzz.category.custom").equals(getCategoryField().getSelectedItem());
	}
	private boolean isJBroFuzzCategory() {
		return ((String)getCategoryField().getSelectedItem()).startsWith(MultiExtensionFuzz.JBROFUZZ_CATEGORY_PREFIX);
	}
	private boolean isCustomCategory(Integer index) {
		return extension.getMessageString("fuzz.category.custom").equals(getCategoryField().getModel().getElementAt(index));
	}
	private boolean isJBroFuzzCategory(Integer index) {
		return ((String)getCategoryField().getModel().getElementAt(index)).startsWith(MultiExtensionFuzz.JBROFUZZ_CATEGORY_PREFIX);
	}
	
	private void setDefaultCategory() {
		this.getCategoryField().setSelectedItem(extension.getDefaultCategory());
	}
	
	protected class StartFuzzAction extends AbstractAction {

        private static final long serialVersionUID = -961522394390805325L;

        public StartFuzzAction() {
            super(extension.getMessageString("fuzz.button.start"));
            setEnabled(false);
        }
        
        @Override
	    public void actionPerformed(ActionEvent e) {
			for(FuzzGap g: gaps){
				List<Integer> indices = g.getIndices();
				try {
					int category = indices.get(0);
					String cat = getCategoryField().getModel().getElementAt(category);
					if (isCustomCategory(category)) {
						for (int i = 1; i < indices.size(); i++) {
							String name = getExtension().getCustomFileList().get(indices.get(i));
							g.addFuzzer(getExtension().getCustomFileFuzzer(name));
						}
					} else if (isJBroFuzzCategory(category)) {
						for (int i = 1; i < indices.size(); i++) {
							String name = getExtension().getJBroFuzzFuzzerNames(cat).get(indices.get(i));
							g.addFuzzer(getExtension().getJBroFuzzer(name));
						}
					} else {
						for (int i = 1; i < indices.size(); i++) {
							String name = getExtension().getFileFuzzerNames(cat).get(indices.get(i));
							g.addFuzzer(getExtension().getFileFuzzer(cat, name));
						}
					}
				}
				catch (NoSuchFuzzerException ex) {
				}
			}
			getExtension().startFuzzers(gaps, getFuzzProcessFactory());
			setVisible(false);
	    }
	}
	
    protected class CancelFuzzAction extends AbstractAction {

        private static final long serialVersionUID = -6716179197963523133L;

        public CancelFuzzAction() {
            super(extension.getMessageString("fuzz.button.cancel"));
        }
        
        @Override
        public void actionPerformed(ActionEvent e) {
            setVisible(false);
        }
    }
	private class AddFuzzAction extends AbstractAction {

		private static final long serialVersionUID = -961522394390805325L;

		public AddFuzzAction() {
			super(extension.getMessageString("fuzz.button.add.add"));
			setEnabled(false);
		}

		@Override
		public void actionPerformed(ActionEvent e) {
			if(adding){
				if(addComponent(new FuzzGap(messageContent.currentSelection(), fuzzableMessage))){
					setSelection(gaps.size() - 1);
					getAddComponentButton().setText(extension.getMessageString("fuzz.button.add.add"));
					info.setText("");
					getStartButton().setEnabled(false);
					getDelComponentButton().setEnabled(true);
					adding = false;
				}
				else{
					JOptionPane.showMessageDialog(null, extension.getMessageString("fuzz.warning.intervalOverlap"));
				}
			}
			else{
				info.setText(extension.getMessageString("fuzz.label.info.instr"));
				getAddComponentButton().setText(extension.getMessageString("fuzz.button.add.done"));
				adding = true;
			}
		}
	}
	private class DelFuzzAction extends AbstractAction {

		private static final long serialVersionUID = -961522394390805325L;

		public DelFuzzAction() {
			super(extension.getMessageString("fuzz.button.del"));
			setEnabled(false);
		}

		@Override
		public void actionPerformed(ActionEvent e) {
			gaps.remove(currentIndex);
			setSelection(currentIndex - 1);
			if(gaps.size() <= 1){
				getDelComponentButton().setEnabled(false);
			}
		}
	}
	private class ColorLine extends JPanel {

		public void paintComponent(Graphics g) {
			super.paintComponent(g);
			for(int i = 0; i < gaps.size(); i++){
				if(i == currentIndex){
					g.setColor(Color.black);
					Rectangle r = new Rectangle(15*i+1, 1, 10, 10);  
					g.fillRect(15*i, 0, 13, 13);
				}
				g.setColor(getColor(i+1));
				g.fillRect(15*i+1, 1, 10, 10);
			}
		}
	}

}
