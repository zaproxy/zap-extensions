package org.zaproxy.zap.extension.exportReport.Utility;

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
 * This file is based on the Paros code file ReportLastScan.java
 */

import java.awt.Color;
import java.awt.Insets;
import java.awt.GridBagLayout;
import java.awt.GridBagConstraints;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import java.util.Arrays;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.SortedSet;
import java.util.TreeSet;

import javax.swing.ListCellRenderer;
import javax.swing.AbstractListModel;
import javax.swing.ListModel;
import javax.swing.JList;
import javax.swing.JLabel;
import javax.swing.JTextField;
import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.BorderFactory;

import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;

import org.parosproxy.paros.Constant;

/*
 * AUTHOR		:	GORAN SARENKAPA - JordanGS
 * SPONSOR		:	RYERSON UNIVERSITY
 * CLASS		:	DualListBox.java 
 * DESC			:	Modified version of the Java Dual List Box Example with additional methods. 
 * CREATED ON	:	MARCH 10TH, 2016
 * CURRENT VER	:	V1.0
 * SOURCE		:	https://github.com/JordanGS/workspace/tree/master/zap-extensions/src/org/zaproxy/zap/extension/exportReport
 * REFERENCE	:	http://www.java2s.com/Tutorial/Java/0240__Swing/DualListBoxSample.htm
 */

/* 
 * MODIFED BY	:	<NAME> - <GIT USER>
 * MOD DATE		:	
 * MOD VERSION	:	<VERSION OF PLUGIN>
 * MOD DESC		:	
 */

public class DualListBox extends JPanel
{
	private static final Insets	EMPTY_INSETS				= new Insets(0, 0, 0, 0);
	private static final String	ADD_BUTTON_LABEL			= ">>";
	private static final String	REMOVE_BUTTON_LABEL			= "<<";
	private static final String	DEFAULT_TITLE				= "";
	private static final String	DEFAULT_SOURCE_CHOICE_LABEL	= Constant.messages
			.getString("exportReport.risk.included");;
	private static final String	DEFAULT_DEST_CHOICE_LABEL	= Constant.messages
			.getString("exportReport.risk.excluded");;
	private JTextField			title;
	private JLabel				sourceLabel;
	private JList				sourceList;
	private SortedListModel		sourceListModel;
	private JList				destList;
	private SortedListModel		destListModel;
	private JLabel				destLabel;
	private JButton				addButton;
	private JButton				removeButton;

	public DualListBox()
	{
		initScreen();
	}

	private String getSourceChoicesTitle()
	{
		return sourceLabel.getText();
	}

	private void setSourceChoicesTitle(String newValue)
	{
		sourceLabel.setText(newValue);
	}

	private String getDestinationChoicesTitle()
	{
		return destLabel.getText();
	}

	private void setDestinationChoicesTitle(String newValue)
	{
		destLabel.setText(newValue);
	}

	private void clearSourceListModel()
	{
		sourceListModel.clear();
	}

	private void clearDestinationListModel()
	{
		destListModel.clear();
	}

	public void addSourceElements(ListModel newValue)
	{
		fillListModel(sourceListModel, newValue);
	}

	private void setSourceElements(ListModel newValue)
	{
		clearSourceListModel();
		addSourceElements(newValue);
	}

	public void addDestinationElements(ListModel newValue)
	{
		fillListModel(destListModel, newValue);
	}

	private void fillListModel(SortedListModel model, ListModel newValues)
	{
		int size = newValues.getSize();
		for (int i = 0; i < size; i++)
		{
			model.add(newValues.getElementAt(i));
		}
	}

	public void addSourceElements(Object newValue[])
	{
		fillListModel(sourceListModel, newValue);
	}

	private void setSourceElements(Object newValue[])
	{
		clearSourceListModel();
		addSourceElements(newValue);
	}

	public void addDestinationElements(Object newValue[])
	{
		fillListModel(destListModel, newValue);
	}

	private void fillListModel(SortedListModel model, Object newValues[])
	{
		model.addAll(newValues);
	}

	private Iterator sourceIterator()
	{
		return sourceListModel.iterator();
	}

	private Iterator destinationIterator()
	{
		return destListModel.iterator();
	}

	private void setSourceCellRenderer(ListCellRenderer newValue)
	{
		sourceList.setCellRenderer(newValue);
	}

	private ListCellRenderer getSourceCellRenderer()
	{
		return sourceList.getCellRenderer();
	}

	private void setDestinationCellRenderer(ListCellRenderer newValue)
	{
		destList.setCellRenderer(newValue);
	}

	private ListCellRenderer getDestinationCellRenderer()
	{
		return destList.getCellRenderer();
	}

	private void setVisibleRowCount(int newValue)
	{
		sourceList.setVisibleRowCount(newValue);
		destList.setVisibleRowCount(newValue);
	}

	private int getVisibleRowCount()
	{
		return sourceList.getVisibleRowCount();
	}

	private void setSelectionBackground(Color newValue)
	{
		sourceList.setSelectionBackground(newValue);
		destList.setSelectionBackground(newValue);
	}

	private Color getSelectionBackground()
	{
		return sourceList.getSelectionBackground();
	}

	private void setSelectionForeground(Color newValue)
	{
		sourceList.setSelectionForeground(newValue);
		destList.setSelectionForeground(newValue);
	}

	private Color getSelectionForeground()
	{
		return sourceList.getSelectionForeground();
	}

	private void removeSourceSelected()
	{
		Object selected[] = sourceList.getSelectedValues();
		for (int i = selected.length - 1; i >= 0; --i)
		{
			sourceListModel.removeElement(selected[i]);
		}
	}

	private void removeDestinationSelected()
	{
		Object selected[] = destList.getSelectedValues();
		for (int i = selected.length - 1; i >= 0; --i)
		{
			destListModel.removeElement(selected[i]);
		}
	}

	private void clearSelected()
	{
		title.setText("");
		sourceList.getSelectionModel().clearSelection();
		destList.getSelectionModel().clearSelection();
	}

	public ArrayList<String> getSourceListModel()
	{
		ArrayList<String> list = new ArrayList<String>();
		for (int i = 0; i < sourceListModel.getSize(); ++i)
		{
			list.add(fixString(sourceListModel.getElementAt(i).toString()));
		}
		return list;
	}

	public void printSource(ArrayList<String> list)
	{
		String str = "";
		for (int i = 0; i < list.size(); i++)
		{
			System.out.println(fixString((String) list.get(i)));
		}
	}

	public String fixString(String str)
	{
		str = str.replaceAll("\\d+\\.\\s", "");
		return str;
	}

	public boolean containsItem(SortedListModel list, String search)
	{
		return true;
	}

	private void initScreen()
	{
		setBorder(BorderFactory.createEtchedBorder());
		setLayout(new GridBagLayout());
		title = new JTextField("");
		title.setEditable(false);
		add(title, new GridBagConstraints(0, 0, 3, 1, 0, 0, GridBagConstraints.CENTER, GridBagConstraints.BOTH,
				EMPTY_INSETS, 0, 0));

		sourceLabel = new JLabel(DEFAULT_SOURCE_CHOICE_LABEL);
		sourceListModel = new SortedListModel();

		sourceList = new JList(sourceListModel);
		sourceList.addListSelectionListener(new AddSelectionListener());
		add(sourceLabel, new GridBagConstraints(0, 1, 1, 1, 0, 0, GridBagConstraints.CENTER, GridBagConstraints.NONE,
				EMPTY_INSETS, 0, 0));
		add(new JScrollPane(sourceList), new GridBagConstraints(0, 2, 1, 5, .5, 1, GridBagConstraints.CENTER,
				GridBagConstraints.BOTH, EMPTY_INSETS, 0, 0));

		addButton = new JButton(ADD_BUTTON_LABEL);
		add(addButton, new GridBagConstraints(1, 3, 1, 2, 0, .25, GridBagConstraints.CENTER, GridBagConstraints.NONE,
				EMPTY_INSETS, 0, 0));
		addButton.addActionListener(new AddListener());
		removeButton = new JButton(REMOVE_BUTTON_LABEL);
		add(removeButton, new GridBagConstraints(1, 5, 1, 2, 0, .25, GridBagConstraints.CENTER, GridBagConstraints.NONE,
				new Insets(0, 5, 0, 5), 0, 0));
		removeButton.addActionListener(new RemoveListener());

		destLabel = new JLabel(DEFAULT_DEST_CHOICE_LABEL);
		destListModel = new SortedListModel();

		destList = new JList(destListModel);
		destList.addListSelectionListener(new RemoveSelectionListener());
		add(destLabel, new GridBagConstraints(2, 1, 1, 1, 0, 0, GridBagConstraints.CENTER, GridBagConstraints.NONE,
				EMPTY_INSETS, 0, 0));
		add(new JScrollPane(destList), new GridBagConstraints(2, 2, 1, 5, .5, 1.0, GridBagConstraints.CENTER,
				GridBagConstraints.BOTH, EMPTY_INSETS, 0, 0));
	}

	public class AddListener implements ActionListener
	{
		public void actionPerformed(ActionEvent e)
		{
			Object selected[] = sourceList.getSelectedValues();
			if (selected.length != 0)
			{
				addDestinationElements(selected);
				removeSourceSelected();
			}
			clearSelected();
		}
	}

	public class RemoveListener implements ActionListener
	{
		public void actionPerformed(ActionEvent e)
		{
			Object selected[] = destList.getSelectedValues();
			if (selected.length != 0)
			{
				addSourceElements(selected);
				removeDestinationSelected();
			}
			clearSelected();
		}
	}

	public class AddSelectionListener implements ListSelectionListener
	{
		public void valueChanged(ListSelectionEvent e)
		{
			if (!e.getValueIsAdjusting())
			{
				if (!sourceList.isSelectionEmpty())
					title.setText(fixString(sourceList.getSelectedValue().toString()));
			}
		}
	}

	public class RemoveSelectionListener implements ListSelectionListener
	{
		public void valueChanged(ListSelectionEvent e)
		{
			if (!e.getValueIsAdjusting())
			{
				if (!destList.isSelectionEmpty())
					title.setText(fixString(destList.getSelectedValue().toString()));
			}
		}
	}

}

class SortedListModel extends AbstractListModel
{

	SortedSet model;

	public SortedListModel()
	{
		model = new TreeSet();
	}

	public int getSize()
	{
		return model.size();
	}

	public Object getElementAt(int index)
	{
		return model.toArray()[index];
	}

	public void add(Object element)
	{
		if (model.add(element))
		{
			fireContentsChanged(this, 0, getSize());
		}
	}

	public void addAll(Object elements[])
	{
		Collection c = Arrays.asList(elements);
		model.addAll(c);
		fireContentsChanged(this, 0, getSize());
	}

	public void clear()
	{
		model.clear();
		fireContentsChanged(this, 0, getSize());
	}

	public boolean contains(Object element)
	{
		return model.contains(element);
	}

	public Object firstElement()
	{
		return model.first();
	}

	public Iterator iterator()
	{
		return model.iterator();
	}

	public Object lastElement()
	{
		return model.last();
	}

	public boolean removeElement(Object element)
	{
		boolean removed = model.remove(element);
		if (removed)
		{
			fireContentsChanged(this, 0, getSize());
		}
		return removed;
	}
}