/**
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 * 
 * @author Alessandro Secco: seccoale@gmail.com
 */
package org.zaproxy.zap.extension.zest.dialogs;

import java.awt.Dimension;
import java.awt.Frame;
import java.util.List;

import javax.swing.JComboBox;

import org.zaproxy.zap.extension.zest.ExtensionZest;
import org.zaproxy.zap.extension.zest.ZestFuzzerDelegate.ZestFuzzerFileDelegate;
import org.zaproxy.zap.view.StandardFieldsDialog;

public class ZestFuzzerCategoryDialog extends StandardFieldsDialog {
	
	private static final long serialVersionUID = 8128872516912291657L;
	
	private ExtensionZest extension=null;
	private Frame owner=null;
	
	private final static String SELECT_CATEGORY_COMBO_BOX="zest.dialog.fuzz.label.category";

	private final JComboBox<String> categorySelectorCb=new JComboBox<>();
	private ZestFuzzerFileDelegate fuzzFile=null;

	
	public ZestFuzzerCategoryDialog(ExtensionZest ext, Frame owner, Dimension dim) {
		super(owner, "zest.dialog.fuzzfile.add.category", dim);
		this.extension=ext;
	}
	
	public void init(ZestFuzzerFileDelegate file, Frame owner){
		this.fuzzFile=file;
		this.owner=owner;
		List<String> categories=extension.getFuzzerDelegate().getJBroFuzzCategories();
		for(String item:categories){
			categorySelectorCb.addItem(item);
		}
		this.add(categorySelectorCb);
		this.addPadding();
	}

	@Override
	public void save() {
		extension.getFuzzerDelegate().addFuzzFile(this.getStringValue(SELECT_CATEGORY_COMBO_BOX), fuzzFile);
	}

	@Override
	public String validateFields() {
		return null;
	}
	

}
