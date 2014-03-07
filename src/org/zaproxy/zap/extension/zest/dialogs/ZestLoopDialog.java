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
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileNotFoundException;
import java.util.List;

import org.apache.log4j.Logger;
import org.mozilla.zest.core.v1.ZestLoop;
import org.mozilla.zest.core.v1.ZestLoopFile;
import org.mozilla.zest.core.v1.ZestLoopInteger;
import org.mozilla.zest.core.v1.ZestLoopString;
import org.mozilla.zest.core.v1.ZestLoopTokenFileSet;
import org.mozilla.zest.core.v1.ZestLoopTokenIntegerSet;
import org.mozilla.zest.core.v1.ZestLoopTokenStringSet;
import org.mozilla.zest.core.v1.ZestStatement;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zap.extension.zest.ExtensionZest;
import org.zaproxy.zap.extension.zest.ZestZapUtils;
import org.zaproxy.zap.view.StandardFieldsDialog;

public class ZestLoopDialog extends StandardFieldsDialog {
	private static final long serialVersionUID = 3720969585202318312L;

	private ExtensionZest extension = null;
	private ScriptNode parent = null;
	private List<ScriptNode> children = null;
	private ZestStatement request = null;
	private ZestLoop<?> loop = null;
	private boolean add = false;
	private boolean surround = false;

	private final static String VARIABLE_NAME = "zest.dialog.loop.variable.name";

	private final static String VALUES_STRING = "zest.dialog.loop.string.values";

	private final static String CATEGORY_FUZZ = "zest.dialog.loop.file.fuzz.categories";
	private final static String FILE_FUZZ = "zest.dialog.loop.file.fuzz.files";
	private final static String FILE_PATH = "zest.dialog.loop.file.fuzz.path";

	private final static String START_INTEGER = "zest.dialog.loop.integer.start";
	private final static String END_INTEGER = "zest.dialog.loop.integer.end";
	private final static String STEP_INTEGER = "zest.dialog.loop.integer.step";

	private static final Logger logger = Logger.getLogger(ZestLoopDialog.class);

	public ZestLoopDialog(ExtensionZest extension, Frame owner, Dimension dim) {
		super(owner, "zest.dialog.loop.add.title", dim);
		this.extension = extension;
	}

	public void init(ScriptNode parent, List<ScriptNode> children,
			ZestStatement req, ZestLoop<?> loop, boolean add, boolean surround) {
		this.add = add;
		this.parent = parent;
		this.children = children;
		this.request = req;
		this.loop = loop;
		this.surround = surround;
		this.removeAllFields();

		if (add) {
			this.setTitle(Constant.messages.getString("zest.dialog.loop.add.title"));
		} else {
			this.setTitle(Constant.messages.getString("zest.dialog.loop.edit.title"));
		}
		this.addTextField(VARIABLE_NAME, loop.getVariableName());
		if (loop instanceof ZestLoopString) {
			drawLoopStringDialog((ZestLoopString) this.loop);
		} else if (loop instanceof ZestLoopFile) {
			drawLoopFileDialog((ZestLoopFile) this.loop);
		} else if (loop instanceof ZestLoopInteger) {
			drawLoopIntegerDialog((ZestLoopInteger) this.loop);
		} else {
			throw new IllegalStateException("Unknown loop type: "
					+ this.loop.getClass().getCanonicalName());
		}
		this.addPadding();
	}

	private void drawLoopStringDialog(ZestLoopString loop) {
		if (loop.getValues() != null) {
			StringBuilder allValues = new StringBuilder();
			for (String token : loop.getValues()) {
				allValues.append(token);
				allValues.append("\n");
			}
			this.addMultilineField(VALUES_STRING, allValues.toString());
		} else {
			this.addMultilineField(VALUES_STRING, "");
		}
	}

	private void drawLoopFileDialog(ZestLoopFile loop) {
		String path = "";
		if (loop.getFile() != null) {
			path = loop.getFile().getAbsolutePath();
		}
		
		this.addComboField(CATEGORY_FUZZ, extension.getFuzzerDelegate().getAllFuzzCategories(), "");
		this.addComboField(FILE_FUZZ, 
				extension.getFuzzerDelegate().getFuzzersForCategory(this.getStringValue(CATEGORY_FUZZ)), "");
		// TODO replace with a file selector when one is available
		this.addTextField(FILE_PATH, path);
		this.addFieldListener(CATEGORY_FUZZ, new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent arg0) {
				setComboFields(FILE_FUZZ, 
						extension.getFuzzerDelegate().getFuzzersForCategory(getStringValue(CATEGORY_FUZZ)),"");
			}
		});
		this.addFieldListener(FILE_FUZZ, new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent arg0) {
				File f = extension.getFuzzerDelegate().getFuzzerFile(
						getStringValue(CATEGORY_FUZZ), getStringValue(FILE_FUZZ));

				if (f != null && f.exists()) {
					setFieldValue(FILE_PATH, f.getAbsolutePath());
				}
			}
		});
		
	}

	private void drawLoopIntegerDialog(ZestLoopInteger loop) {
		this.addNumberField(START_INTEGER, Integer.MIN_VALUE,
				Integer.MAX_VALUE, loop.getStart());
		this.addNumberField(END_INTEGER, Integer.MIN_VALUE, Integer.MAX_VALUE,
				loop.getEnd());
		this.addNumberField(STEP_INTEGER, 1, Integer.MAX_VALUE,
				loop.getCurrentToken());
	}

	@Override
	public void save() {
		if (this.loop instanceof ZestLoopString) {
			ZestLoopString loopString=(ZestLoopString) this.loop;
			ZestLoopTokenStringSet newSet=new ZestLoopTokenStringSet();
			String [] strs = this.getStringValue(VALUES_STRING).split("\n");
			for (String str : strs) {
				newSet.addToken(str);
			}
			loopString.setSet(newSet);
		} else if (this.loop instanceof ZestLoopFile) {
			ZestLoopFile loopFile=(ZestLoopFile) this.loop;
			try {
				File selectedFile = new File(this.getStringValue(FILE_PATH));
				ZestLoopTokenFileSet fileSet=new ZestLoopTokenFileSet(selectedFile.getAbsolutePath());
				loopFile.setSet(fileSet);
			} catch (FileNotFoundException e) {
				logger.error(e.getMessage(), e);
			}
		} else if (this.loop instanceof ZestLoopInteger) {
			ZestLoopInteger loopInteger=(ZestLoopInteger) this.loop;
			int start=this.getIntValue(START_INTEGER);
			int end=this.getIntValue(END_INTEGER);
			int step=this.getIntValue(STEP_INTEGER);
			ZestLoopTokenIntegerSet newSet=new ZestLoopTokenIntegerSet(start, end);
			loopInteger.setSet(newSet);
			loopInteger.setStep(step);
		}
		this.loop.setVariableName(this.getStringValue(VARIABLE_NAME));
		if (add) {
			if (request == null) {
				if (surround) {
					for(ScriptNode node:children){
						extension.delete(node);
						ZestStatement stmt=(ZestStatement)ZestZapUtils.getElement(node);
						loop.addStatement(stmt);
					}
				}
				extension.addToParent(parent, this.loop);
			} else {
				for (ScriptNode child : children) {
					extension.addAfterRequest(parent, child, request, this.loop);
				}
			}
		} else {
			for (ScriptNode child : children) {
				extension.updated(child);
				extension.display(child, true);
			}
		}
	}

	@Override
	public String validateFields() {
		if (! ZestZapUtils.isValidVariableName(this.getStringValue(VARIABLE_NAME))) {
			return Constant.messages.getString("zest.dialog.loop.string.error.variable");
		}

		if (this.loop instanceof ZestLoopString) {
			if (this.isEmptyField(VALUES_STRING)) {
				return Constant.messages.getString("zest.dialog.loop.string.error.values");
			}
		} else if (this.loop instanceof ZestLoopFile) {
			File fileProposed = new File(this.getStringValue(FILE_PATH));
			if (fileProposed == null || !fileProposed.exists()) {
				return Constant.messages.getString("zest.dialog.loop.file.error.nonexisting");
			}
		} else if (this.loop instanceof ZestLoopInteger) {
			if (this.getIntValue(START_INTEGER) > this.getIntValue(END_INTEGER)) {
				return Constant.messages.getString("zest.dialog.loop.integer.error.constraints");
			}
		}
		return null;
	}
}
