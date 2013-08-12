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
import java.awt.Rectangle;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.List;
import java.util.StringTokenizer;

import javax.swing.BoxLayout;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;

import org.mozilla.zest.core.v1.ZestLoop;
import org.mozilla.zest.core.v1.ZestLoopFile;
import org.mozilla.zest.core.v1.ZestLoopInteger;
import org.mozilla.zest.core.v1.ZestLoopString;
import org.mozilla.zest.core.v1.ZestStatement;
import org.owasp.jbrofuzz.core.Fuzzer;
import org.owasp.jbrofuzz.core.NoSuchFuzzerException;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.FileCopier;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.fuzz.FileFuzzer;
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zap.extension.zest.ExtensionZest;
import org.zaproxy.zap.extension.zest.ZestFuzzerDelegate;
import org.zaproxy.zap.extension.zest.ZestFuzzerDelegate.ZestFuzzerFileDelegate;
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

	private static final String FILE_NAME_LABEL = "zest.dialog.loop.label.filename";
	private static final String FILE_NAME_BUTTON_BROWSE = "zest.dialog.loop.button.browse.filename";
	private static final String SELECT_FUZZFILE_BUTTON_BROWSE = "zest.dialog.loop.button.select.fuzzfile";
	private static final String STRING_LABEL = "zest.dialog.loop.label.string";
	private static final String INT_LABEL_START = "zest.dialog.loop.label.int.start";
	private static final String INT_LABEL_END = "zest.dialog.loop.label.int.end";
	private static final String ADD_TO_FUZZER_FILES_CHECK_BOX = "zest.dialog.loop.add.fuzzfile";

	private JButton browseFileBTN = null;// TODO set icon
	private JButton selectFuzzBTN = null;// TODO set icon
	private JComboBox<String> fuzzCatCB = null;
	private DefaultComboBoxModel<String> fuzzModelDCB = null;
	private JList<String> fuzzerField = null;
	private JCheckBox addToFuzzerCB = null;
	private JTextField pathToFileTF = null;
	private final JLabel setFileNameLbl = new JLabel(
			Constant.messages.getString(FILE_NAME_LABEL));

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
			String allValues = "";
			for (String token : loop.getValues()) {
				allValues += " " + token;
			}
			allValues.substring(1);
			this.addTextField(STRING_LABEL, allValues);
		} else {
			this.addTextField(STRING_LABEL, "");
		}
	}

	private void initFrameLoopFile() {
		this.setBounds(new Rectangle(900, 500));
	}

	private JPanel getContentPanelLoopFile() {
		JPanel content = new JPanel();
		content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));
		content.add(setFileNameLbl);
		content.add(getFirstLineLoopFile());
		content.add(getFuzzerCategorySelectorLoopFile());
		content.add(getSecondLineLoopFile());
		content.add(getFuzzerFieldLoopFile());

		return content;
	}

	private JPanel getFirstLineLoopFile() {
		JPanel firstLine = new JPanel();
		firstLine.setLayout(new BoxLayout(firstLine, BoxLayout.X_AXIS));
		firstLine.add(getPathToFileTF());
		firstLine.add(getBrowseFileButtonLoopFile());
		firstLine.add(getAddToFuzzerCBLoopFile());
		return firstLine;
	}

	private JTextField getPathToFileTF() {
		if (this.pathToFileTF == null) {
			pathToFileTF = new JTextField();
			if (((ZestLoopFile) loop).getFile() != null) {
				pathToFileTF.setText(((ZestLoopFile) loop).getFile()
						.getAbsolutePath());
			} else {
				pathToFileTF.setText("");
			}
			pathToFileTF.setEditable(true);
			pathToFileTF.setSize(500, pathToFileTF.getHeight());// default
																// height
		}
		return this.pathToFileTF;
	}

	private JButton getBrowseFileButtonLoopFile() {
		if (this.browseFileBTN == null) {
			browseFileBTN = new JButton();
			browseFileBTN.setText(Constant.messages
					.getString(FILE_NAME_BUTTON_BROWSE));
			final File customFuzzerDir = extension.getFuzzerDelegate()
					.getCustomFuzzerDir();
			browseFileBTN.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent arg0) {
					JFileChooser fileChooser = new JFileChooser();
					fileChooser.setCurrentDirectory(customFuzzerDir);
					int rVal;
					fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
					fileChooser.setAcceptAllFileFilterUsed(false);
					rVal = fileChooser.showOpenDialog(null);
					if (rVal == JFileChooser.APPROVE_OPTION) {
						getPathToFileTF().selectAll();
						getPathToFileTF().replaceSelection(fileChooser
								.getSelectedFile().getAbsolutePath());
					}
				}
			});
		}
		return this.browseFileBTN;
	}

	private JPanel getSecondLineLoopFile() {
		JPanel secondLine = new JPanel();
		secondLine.setLayout(new BoxLayout(secondLine, BoxLayout.X_AXIS));
		secondLine.add(getFuzzerCategorySelectorLoopFile());
		secondLine.add(getSelectFuzzBTNLoopFile());
		return secondLine;
	}

	private JButton getSelectFuzzBTNLoopFile() {
		if (selectFuzzBTN == null) {
			selectFuzzBTN = new JButton(
					Constant.messages.getString(SELECT_FUZZFILE_BUTTON_BROWSE));
			selectFuzzBTN.addActionListener(new ActionListener() {// TODO check
						@Override
						public void actionPerformed(ActionEvent arg0) {
							if (getFuzzerFieldLoopFile().getSelectedValue() == null) {
								return;
							}
							String absolutePath = "";
							if (isCustomCategory()) {
								FileFuzzer selected = extension
										.getFuzzerDelegate()
										.getCustomFileFuzzer(
												getFuzzerFieldLoopFile().getSelectedValue());
								System.err.println("Is cstom DIR");
								absolutePath += extension.getFuzzerDelegate()
										.getCustomFuzzerDir().getAbsolutePath();
								absolutePath += File.separator
										+ selected.getFileName();
							} else {
								try {
									Fuzzer selected = extension
											.getFuzzerDelegate()
											.getJBroFuzzer(
													getFuzzerFieldLoopFile()
															.getSelectedValue());
									absolutePath += extension
											.getFuzzerDelegate()
											.fromFuzzer(selected)
											.getAbsolutePath();
								} catch (NoSuchFuzzerException e) {
									e.printStackTrace();
								} catch (IOException e) {
									e.printStackTrace();
								}
							}
							File fuzz = new File(absolutePath);
							if (!fuzz.exists()) {
								System.err.println("Inexisting fuzzer file");
							} else {
								getPathToFileTF().selectAll();
								getPathToFileTF().replaceSelection(fuzz
										.getAbsolutePath());
							}
						}
					});
		}
		return selectFuzzBTN;
	}

	private JComboBox<String> getFuzzerCategorySelectorLoopFile() {
		if (this.fuzzCatCB == null) {
			this.fuzzCatCB = new JComboBox<>();
			fuzzCatCB.setBounds(new Rectangle(100, 50));
			fuzzCatCB.removeAllItems();
			for (String category : extension.getFuzzerDelegate()
					.getJBroFuzzCategories()) {
				fuzzCatCB.addItem(category);
			}
			fuzzCatCB.addItem(Constant.messages
					.getString("fuzz.category.custom"));
			if (fuzzCatCB.getItemCount() == 0) {
				fuzzCatCB.setEnabled(false);
				getSelectFuzzBTNLoopFile().setEnabled(false);
			} else {
				fuzzCatCB.setEnabled(true);
				getSelectFuzzBTNLoopFile().setEnabled(true);
			}
			fuzzCatCB.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent e) {
					if (fuzzCatCB.getSelectedItem() == null) {
						return;
					}
					setFuzzerNames();
				}
			});
			fuzzCatCB.setSelectedIndex(0);
		}

		return this.fuzzCatCB;
	}

	private JList<String> getFuzzerFieldLoopFile() {
		if (fuzzerField == null) {
			fuzzerField = new JList<>();
			fuzzerField.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
			fuzzerField.setModel(fuzzModelDCB);
		}
		return this.fuzzerField;
	}

	private JCheckBox getAddToFuzzerCBLoopFile() {
		if (this.addToFuzzerCB == null) {
			this.addToFuzzerCB = new JCheckBox();
			addToFuzzerCB.setText(Constant.messages
					.getString(ADD_TO_FUZZER_FILES_CHECK_BOX));
			addToFuzzerCB.setSelected(false);
		}
		return addToFuzzerCB;
	}

	private void drawLoopFileDialog(ZestLoopFile loop) {
		initFrameLoopFile();
		this.add(getContentPanelLoopFile(), 0);
		this.addPadding();
	}

	private void setFuzzerNames() {
		if(fuzzModelDCB==null){
			fuzzModelDCB=new DefaultComboBoxModel<>();
		}
		fuzzModelDCB.removeAllElements();
		String category = (String) fuzzCatCB.getSelectedItem();
		if (category == null) {
			;// ignore
		} else {
			if (isCustomCategory()) {
				List<String> fuzzers = extension.getFuzzerDelegate()
						.getCustomFileList();
				for (String fuzzer : fuzzers) {
					fuzzModelDCB.addElement(fuzzer);
				}
			} else if (category
					.startsWith(ZestFuzzerDelegate.JBROFUZZ_CATEGORY_PREFIX)) {
				for (String fuzzer : extension.getFuzzerDelegate()
						.getJBroFuzzFuzzerNames(category)) {
					fuzzModelDCB.addElement(fuzzer);
				}
			} else {
				List<String> fuzzers = extension.getFuzzerDelegate()
						.getFileFuzzerNames(category);
				for (String fuzzer : fuzzers) {
					fuzzModelDCB.addElement(fuzzer);
				}
			}
		}
	}

	private boolean isJBroFuzzCategory() {
		return ((String) fuzzCatCB.getSelectedItem())
				.startsWith(ZestFuzzerDelegate.JBROFUZZ_CATEGORY_PREFIX);
	}

	private boolean isCustomCategory() {
		return Constant.messages.getString("fuzz.category.custom").equals(
				(String) fuzzCatCB.getSelectedItem());
	}

	private void drawLoopIntegerDialog(ZestLoopInteger loop) {
		this.addNumberField(INT_LABEL_START, Integer.MIN_VALUE,
				Integer.MAX_VALUE, loop.getStart());
		this.addNumberField(INT_LABEL_END, Integer.MIN_VALUE,
				Integer.MAX_VALUE, loop.getEnd());
	}

	@Override
	public void save() {
		if (this.loop instanceof ZestLoopString) {
			ZestLoopString loopString = (ZestLoopString) this.loop;
			loopString.getSet().getTokens().clear();
			StringTokenizer st = new StringTokenizer(
					this.getStringValue(STRING_LABEL));
			while (st.hasMoreTokens()) {
				loopString.getSet().addToken(st.nextToken());
			}
		} else if (this.loop instanceof ZestLoopFile) {
			ZestLoopFile loopFile = (ZestLoopFile) this.loop;
			String currentFile = loopFile.getFile().getAbsolutePath();
			String proposedFile = pathToFileTF.getText();
			File selectedFile = new File(proposedFile);
			if (proposedFile.equals(currentFile)) {
				;// do nothing
			} else {

				try {
					loopFile = new ZestLoopFile(proposedFile);

					this.loop = loopFile;
					if (addToFuzzerCB.isSelected()) {
						FileCopier copier = new FileCopier();
						File customDir = extension.getFuzzerDelegate()
								.getCustomFuzzerDir();
						File newFile = new File(customDir.getAbsolutePath()
								+ File.separator + selectedFile.getName());
						if (newFile.exists()) {
							View.getSingleton()
									.showWarningDialog(
											Constant.messages
													.getString("fuzz.add.duplicate.error"));

						} else if (!newFile.getParentFile().canWrite()) {
							View.getSingleton()
									.showWarningDialog(
											Constant.messages
													.getString("fuzz.add.dirperms.error")
													+ newFile.getParentFile()
															.getAbsolutePath());

						}
						try {
							copier.copy(selectedFile, newFile);
							View.getSingleton().showMessageDialog(
									Constant.messages.getString("fuzz.add.ok"));
						} catch (IOException e1) {
							View.getSingleton().showWarningDialog(
									Constant.messages
											.getString("fuzz.add.fail.error")
											+ e1.getMessage());
						}
					}
				} catch (FileNotFoundException e) {
					e.printStackTrace();
				}

			}
		} else if (this.loop instanceof ZestLoopInteger) {
			ZestLoopInteger loopInteger = (ZestLoopInteger) this.loop;
			loopInteger.getSet().setStart(this.getIntValue(INT_LABEL_START));
			loopInteger.getSet().setEnd(this.getIntValue(INT_LABEL_END));
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

	@Override
	public String validateFields() {
		if (this.loop instanceof ZestLoopString) {
			StringTokenizer st = new StringTokenizer(
					this.getStringValue(STRING_LABEL));
			if (!st.hasMoreTokens()) {
				return Constant.messages
						.getString("zest.dialog.loop.string.error.values");
			}
		} else if (this.loop instanceof ZestLoopFile) {
			File proposed = new File(pathToFileTF.getText());
			if (!proposed.exists()) {
				return Constant.messages
						.getString("zest.dialog.loop.file.error.nonexisting");
			}
		} else if (this.loop instanceof ZestLoopInteger) {
			if (this.getIntValue(INT_LABEL_START) > this
					.getIntValue(INT_LABEL_END)) {
				this.loop = new ZestLoopInteger(
						this.getIntValue(INT_LABEL_END),
						this.getIntValue(INT_LABEL_START));
				// it simply inverts start with end generating no error.
			}
		}
		return null;
	}
}
