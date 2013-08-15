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
import java.io.IOException;
import java.util.List;
import java.util.StringTokenizer;

import org.mozilla.zest.core.v1.ZestLoop;
import org.mozilla.zest.core.v1.ZestLoopFile;
import org.mozilla.zest.core.v1.ZestLoopInteger;
import org.mozilla.zest.core.v1.ZestLoopString;
import org.mozilla.zest.core.v1.ZestLoopTokenFileSet;
import org.mozilla.zest.core.v1.ZestLoopTokenIntegerSet;
import org.mozilla.zest.core.v1.ZestLoopTokenStringSet;
import org.mozilla.zest.core.v1.ZestStatement;
import org.owasp.jbrofuzz.core.Fuzzer;
import org.owasp.jbrofuzz.core.NoSuchFuzzerException;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zap.extension.zest.ExtensionZest;
import org.zaproxy.zap.extension.zest.ZestFuzzerDelegate;
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

	private final static String START_INTEGER = "zest.dialog.loop.integer.start";
	private final static String END_INTEGER = "zest.dialog.loop.integer.end";
	private final static String STEP_INTEGER = "zest.dialog.loop.integer.step";

	private File fileProposed = null;

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
			this.setTitle(Constant.messages
					.getString("zest.dialog.loop.add.title"));
		} else {
			this.setTitle(Constant.messages
					.getString("zest.dialog.loop.edit.title"));
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
			String allValues = " ";
			for (String token : loop.getValues()) {
				allValues += token;
			}
			allValues = allValues.substring(1);
			this.addMultilineField(VALUES_STRING, allValues);
		} else {
			this.addMultilineField(VALUES_STRING, "");
		}
	}

	private void drawLoopFileDialog(ZestLoopFile loop) {
		List<String> categories = extension.getFuzzerDelegate()
				.getJBroFuzzCategories();
		categories.add(Constant.messages.getString("fuzz.category.custom"));
		this.addComboField(CATEGORY_FUZZ, categories, "");
		this.addComboField(FILE_FUZZ, extension.getFuzzerDelegate()
				.getJBroFuzzFuzzerNames(this.getStringValue(CATEGORY_FUZZ)), "");
		this.addFieldListener(CATEGORY_FUZZ, new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent arg0) {
				setComboFields(FILE_FUZZ, extension.getFuzzerDelegate()
						.getJBroFuzzFuzzerNames(getStringValue(CATEGORY_FUZZ)),
						"");
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

	private boolean isJBroFuzzCategory(String category) {
		return category.startsWith(ZestFuzzerDelegate.JBROFUZZ_CATEGORY_PREFIX);
	}

	@Override
	public void save() {
		this.loop.setVariableName(this.getStringValue(VARIABLE_NAME));
		if (this.loop instanceof ZestLoopString) {
			ZestLoopString loopString=(ZestLoopString) this.loop;
			StringTokenizer st = new StringTokenizer(
					this.getStringValue(VALUES_STRING));
			ZestLoopTokenStringSet newSet=new ZestLoopTokenStringSet();
			String value="";
			while (st.hasMoreTokens()) {
				value=st.nextToken();
				newSet.addToken(value);
			}
			loopString.setSet(newSet);
		} else if (this.loop instanceof ZestLoopFile) {
			ZestLoopFile loopFile=(ZestLoopFile) this.loop;
			try {
				File selectedFile=this.getFileFromSelection();
				ZestLoopTokenFileSet fileSet=new ZestLoopTokenFileSet(selectedFile.getAbsolutePath());
				loopFile.setSet(fileSet);
			} catch (FileNotFoundException e) {
				e.printStackTrace();
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
		if (add) {
			if (request == null) {
				ScriptNode loopNode = extension.addToParent(parent, this.loop);
				if (surround) {
					extension.setCnpNodes(children);
					extension.setCut(true);
					extension.pasteToNode(loopNode);
				}
			} else {
				for (ScriptNode child : children) {
					extension
							.addAfterRequest(parent, child, request, this.loop);
				}
			}
		} else {
			for (ScriptNode child : children) {
				extension.updated(child);
				extension.display(child, false);
			}
		}
	}

	private File getFileFromSelection() {
		String category = this.getStringValue(CATEGORY_FUZZ);
		String fuzzerName = this.getStringValue(FILE_FUZZ);
		File fuzzerFile = null;
		if (isJBroFuzzCategory(category)) {
			Fuzzer fuzzer;
			try {
				fuzzer = extension.getFuzzerDelegate()
						.getJBroFuzzer(fuzzerName);
				fuzzerFile = extension.getFuzzerDelegate().fromFuzzer(fuzzer);
			} catch (NoSuchFuzzerException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}
		} else {
			String absolutePath = extension.getFuzzerDelegate()
					.getCustomFileFuzzer(fuzzerName).getFileName();
			absolutePath = extension.getFuzzerDelegate().getCustomFuzzerDir()
					.getAbsolutePath()
					+ File.separator + absolutePath;
			fuzzerFile = new File(absolutePath);
		}
		this.fileProposed = fuzzerFile;
		return this.fileProposed;
	}

	@Override
	public String validateFields() {
		if (this.loop instanceof ZestLoopString) {
			StringTokenizer st = new StringTokenizer(
					this.getStringValue(VALUES_STRING));
			if (!st.hasMoreTokens()) {
				return Constant.messages
						.getString("zest.dialog.loop.string.error.values");
			}
		} else if (this.loop instanceof ZestLoopFile) {
			this.fileProposed = this.getFileFromSelection();
			if (!fileProposed.exists()) {
				return Constant.messages
						.getString("zest.dialog.loop.file.error.nonexisting");
			}
		} else if (this.loop instanceof ZestLoopInteger) {
			if (this.getIntValue(START_INTEGER) > this.getIntValue(END_INTEGER)) {
				((ZestLoopInteger) this.loop).getSet().setStart(this.getIntValue(END_INTEGER));
				((ZestLoopInteger) this.loop).getSet().setEnd(this.getIntValue(START_INTEGER));
				// it simply inverts start with end generating no error.
			}
		}
		return null;
	}
}
