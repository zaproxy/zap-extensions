///**
///* This Source Code Form is subject to the terms of the Mozilla Public
// * License, v. 2.0. If a copy of the MPL was not distributed with this
// * file, You can obtain one at http://mozilla.org/MPL/2.0/.
// * 
// * @author Alessandro Secco: seccoale@gmail.com
// */
//package org.zaproxy.zap.extension.zest.dialogs;
//
//import java.awt.Dimension;
//import java.awt.Frame;
//import java.awt.event.ActionEvent;
//import java.awt.event.ActionListener;
//import java.util.HashMap;
//import java.util.LinkedList;
//import java.util.List;
//import java.util.Map;
//import java.util.regex.Matcher;
//import java.util.regex.Pattern;
//
//import javax.swing.Box;
//import javax.swing.BoxLayout;
//import javax.swing.JButton;
//import javax.swing.JComboBox;
//import javax.swing.JLabel;
//import javax.swing.JPanel;
//import javax.swing.JTextField;
//import javax.swing.JTextPane;
//
//import org.mozilla.zest.core.v1.NoSuchExpressionException;
//import org.mozilla.zest.core.v1.ZestConditional;
//import org.mozilla.zest.core.v1.ZestElement;
//import org.mozilla.zest.core.v1.ZestExpression;
//import org.mozilla.zest.core.v1.ZestExpressionElement;
//import org.mozilla.zest.core.v1.ZestExpressionEquals;
//import org.mozilla.zest.core.v1.ZestExpressionLength;
//import org.mozilla.zest.core.v1.ZestExpressionRegex;
//import org.mozilla.zest.core.v1.ZestExpressionResponseTime;
//import org.mozilla.zest.core.v1.ZestExpressionStatusCode;
//import org.mozilla.zest.core.v1.ZestExpressionURL;
//import org.mozilla.zest.core.v1.ZestScript;
//import org.mozilla.zest.core.v1.ZestStatement;
//import org.mozilla.zest.impl.ZestExpressionEvaluator;
//import org.mozilla.zest.impl.ZestUtils;
//import org.parosproxy.paros.Constant;
//import org.zaproxy.zap.extension.script.ScriptNode;
//import org.zaproxy.zap.extension.zest.ExtensionZest;
//import org.zaproxy.zap.extension.zest.ZestZapUtils;
//import org.zaproxy.zap.view.StandardFieldsDialog;
//
//public class ZestComplexConditionDialog extends StandardFieldsDialog {
//
//	private static final long serialVersionUID = -5829267765139331849L;
//
//	private final Map<String, ZestConditional> conditionals = new HashMap<>();
//
//	private ExtensionZest extension = null;
//	private ZestScript script = null;
//	private ScriptNode parent = null;
//	private List<ScriptNode> children = null;
//	private ZestStatement request = null;
//	private ZestExpression expression = null;
//	private boolean add = false;
//	private boolean surround = false;
//	private static final ZestExpressionEvaluator evaluator = new ZestExpressionEvaluator();
//
//	private ZestExpressionDialog childDialog = null;
//	// TODO make other dialogs children of this Frame and not of the ZAP view
//	// singleton!
//
//	private JPanel firstLine = null;
//	private JPanel secondLine = null;
//	private JPanel thirdLine = null;
//	private JPanel fourthLine = null;
//	private JPanel fifthLine = null;
//	private JPanel sixthLine = null;
//	private JPanel seventhLine = null;
//
//	private JLabel description = null;
//	private JLabel collection = null;
//	private JLabel suggest_ComboBox_usage = null;
//	private JLabel variableNameLBL = null;
//
//	private JButton addSimpleConditionBTN = null;
//	private JButton editSimpleConditionBTN = null;
//	private JButton addToComplexConditionBTN = null;
//
//	private JComboBox<ConditionType> addSimpleConditionCB = null;
//	private JComboBox<ZestExpressionElement> addToComplexConditionCB = null;
//
//	private JTextPane complexConditionText = null;
//
//	private JTextField variableName = null;
//
//	public ZestComplexConditionDialog(ExtensionZest ext, Frame owner,
//			Dimension dim) {
//		super(owner, "zest.dialog.complex.condition.add.title", dim);
//		this.extension = ext;
//	}
//
//	private JLabel getVariableNameLBL() {
//		if (this.variableNameLBL == null) {
//			this.variableNameLBL = new JLabel(
//					Constant.messages
//							.getString("zest.dialog.condition.label.variable"));
//		}
//		return this.variableNameLBL;
//	}
//
//	private JTextField getVariableNameTF() {
//		if (variableName == null) {
//			variableName = new JTextField();
//		}
//		return this.variableName;
//	}
//
//	private JPanel getFirstLine() {
//		if (firstLine == null) {
//			firstLine = new JPanel();
//			firstLine.setLayout(new BoxLayout(firstLine, BoxLayout.X_AXIS));
//			firstLine.add(this.getVariableNameLBL());
//			firstLine.add(this.getVariableNameTF());
//		}
//		return firstLine;
//	}
//
//	private JPanel getSecondLine() {
//		if (secondLine == null) {
//			secondLine = new JPanel();
//			secondLine.setLayout(new BoxLayout(secondLine, BoxLayout.X_AXIS));
//			secondLine.add(getDescriptionLabel());
//		}
//		return secondLine;
//	}
//
//	private JPanel getThirdLine() {
//		if (thirdLine == null) {
//			thirdLine = new JPanel();
//			thirdLine.setLayout(new BoxLayout(thirdLine, BoxLayout.X_AXIS));
//			thirdLine.add(getAddSimpleConditionCB());
//			thirdLine.add(getAddSimpleConditionBTN());
//		}
//		return thirdLine;
//	}
//
//	private JPanel getFourthLine() {
//		if (fourthLine == null) {
//			fourthLine = new JPanel();
//			fourthLine.setLayout(new BoxLayout(fourthLine, BoxLayout.X_AXIS));
//			fourthLine.add(getCollectionLabel());
//		}
//		return fourthLine;
//	}
//
//	private JPanel getFifthLine() {
//		if (fifthLine == null) {
//			fifthLine = new JPanel();
//			fifthLine.setLayout(new BoxLayout(fifthLine, BoxLayout.X_AXIS));
//			fifthLine.add(getAddToComplexConditionCB());
//			fifthLine.add(getAddToComplexConditionBTN());
//			fifthLine.add(getEditSimpleConditionBTN());
//		}
//		return fifthLine;
//	}
//
//	private JPanel getSixthLine() {
//		if (sixthLine == null) {
//			sixthLine = new JPanel();
//			sixthLine.setLayout(new BoxLayout(sixthLine, BoxLayout.X_AXIS));
//			sixthLine.add(getSuggestedUsageLabel());
//		}
//		return sixthLine;
//	}
//
//	private JPanel getSeventhLine() {
//		if (seventhLine == null) {
//			seventhLine = new JPanel();
//			seventhLine.setLayout(new BoxLayout(seventhLine, BoxLayout.X_AXIS));
//			seventhLine.add(getComplexConditionText());
//		}
//		return seventhLine;
//	}
//
//	private JPanel getContentPaneComplexCondition() {
//		JPanel content = new JPanel();
//		content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));
//		content.add(getFirstLine());
//		content.add(getSecondLine());
//		content.add(Box.createGlue());
//		content.add(getThirdLine());
//		content.add(Box.createGlue());
//		content.add(getFourthLine());
//		content.add(getFifthLine());
//		content.add(Box.createGlue());
//		content.add(getSixthLine());
//		content.add(getSeventhLine());
//		return content;
//	}
//
//	private JTextPane getComplexConditionText() {
//		if (complexConditionText == null) {
//			complexConditionText = new JTextPane();
//		}
//		return complexConditionText;
//	}
//
//	public void addSimpleCondition(ZestConditional condition) {
//		getAddToComplexConditionCB().addItem(condition.getRootExpression());
//		conditionals.put(condition.toString(),
//				(ZestConditional) condition.deepCopy());
//	}
//
//	private JComboBox<ZestExpressionElement> getAddToComplexConditionCB() {
//		if (addToComplexConditionCB == null) {
//			addToComplexConditionCB = new JComboBox<>();
//		}
//		return addToComplexConditionCB;
//	}
//
//	private JComboBox<ConditionType> getAddSimpleConditionCB() {
//		if (addSimpleConditionCB == null) {
//			addSimpleConditionCB = new JComboBox<>();
//			for (ConditionType type : ConditionType.values()) {
//				addSimpleConditionCB.addItem(type);
//			}
//		}
//		return addSimpleConditionCB;
//	}
//
//	private JButton getAddToComplexConditionBTN() {
//		if (addToComplexConditionBTN == null) {
//			addToComplexConditionBTN = new JButton(
//					Constant.messages
//							.getString("zest.dialog.complex.condition.addto.complex.btn"));
//			addToComplexConditionBTN.addActionListener(new ActionListener() {
//
//				@Override
//				public void actionPerformed(ActionEvent paramActionEvent) {
//					getComplexConditionText().setText(
//							getComplexConditionText().getText()
//									+ " ( "
//									+ getAddToComplexConditionCB()
//											.getSelectedItem() + " ) ");// TODO
//					// made not editable!
//					// And maybe with color!
//				}
//			});
//		}
//		return addToComplexConditionBTN;
//	}
//
//	private final ZestComplexConditionDialog getThis() {
//		return this;
//	}
//
//	private JButton getAddSimpleConditionBTN() {
//		if (addSimpleConditionBTN == null) {
//			addSimpleConditionBTN = new JButton(
//					Constant.messages
//							.getString("zest.dialog.complex.condition.addto.btn"));
//			addSimpleConditionBTN.addActionListener(new ActionListener() {
//
//				@Override
//				public void actionPerformed(ActionEvent paramActionEvent) {
//					if (childDialog == null) {
//						childDialog = new ZestComponentOfStructuredConditionDialog(
//								extension, getThis(), new Dimension(300, 200));
//					}
//					if (childDialog.isVisible()) {
//						return;// do nothing.
//					}
//					ZestExpression expr = null;
//					switch ((ConditionType) addSimpleConditionCB
//							.getSelectedItem()) {
//					case URL:
//						expr = new ZestExpressionURL();
//						break;
//					case REGEX:
//						expr = new ZestExpressionRegex();
//						break;
//					case TIME_RESPONSE:
//						expr = new ZestExpressionResponseTime();
//						break;
//					case STATUS_CODE:
//						expr = new ZestExpressionStatusCode();
//						break;
//					case EQUALS:
//						expr = new ZestExpressionEquals();
//					}
//					if (expr == null) {
//						throw new IllegalArgumentException(
//								"non existing expression");
//					}
//					childDialog.init(script, parent, children, request, expr,
//							false, false, false);
//					childDialog.setVisible(true);
//				}
//			});
//		}
//		return addSimpleConditionBTN;
//	}
//
//	private JButton getEditSimpleConditionBTN() {
//		if (this.editSimpleConditionBTN == null) {
//			this.editSimpleConditionBTN = new JButton(
//					Constant.messages
//							.getString("zest.dialog.complex.condition.edit.btn"));
//			this.editSimpleConditionBTN.addActionListener(new ActionListener() {
//
//				@Override
//				public void actionPerformed(ActionEvent e) {
//					if (childDialog == null) {
//						childDialog = new ZestComponentOfStructuredConditionDialog(
//								extension, getThis(), new Dimension(300, 200));
//					}
//					if (childDialog.isVisible()) {
//						return;// do nothing.
//					}
//					ZestConditional condition = new ZestConditional();
//					ZestExpression expr = (ZestExpression) getAddToComplexConditionCB()
//							.getSelectedItem();
//					condition.setRootExpression(expr);
//					childDialog.init(script, parent, children, request, expr,
//							false, false, false);
//				}
//			});
//			this.editSimpleConditionBTN.setEnabled(false);
//		}
//		return this.editSimpleConditionBTN;
//	}
//
//	protected void enableEditSimpleConditionBTN(boolean enabled) {
//		this.getEditSimpleConditionBTN().setEnabled(enabled);
//	}
//
//	private JLabel getSuggestedUsageLabel() {
//		if (suggest_ComboBox_usage == null) {
//			suggest_ComboBox_usage = new JLabel(
//					Constant.messages
//							.getString("zest.dialog.complex.condition.suggest"));
//		}
//		return suggest_ComboBox_usage;
//	}
//
//	private JLabel getCollectionLabel() {
//		if (collection == null) {
//			collection = new JLabel(
//					Constant.messages
//							.getString("zest.dialog.complex.condition.collection"));
//		}
//		return collection;
//	}
//
//	private JLabel getDescriptionLabel() {
//		if (description == null) {
//			description = new JLabel(
//					Constant.messages
//							.getString("zest.dialog.complex.condition.description"));
//		}
//		return description;
//	}
//
//	private void fillAddToComplexConditionComboBox(String structuredExpression)
//			throws NoSuchExpressionException {
//		List<Pattern> simpleConditionalPatterns = new LinkedList<>();
//		simpleConditionalPatterns.add(ZestExpressionEquals.getPattern());
//		simpleConditionalPatterns.add(ZestExpressionLength.getPattern());
//		simpleConditionalPatterns.add(ZestExpressionRegex.getPattern());
//		simpleConditionalPatterns.add(ZestExpressionResponseTime.getPattern());
//		simpleConditionalPatterns.add(ZestExpressionStatusCode.getPattern());
//		simpleConditionalPatterns.add(ZestExpressionURL.getPattern());
//		for (Pattern pattern : simpleConditionalPatterns) {
//			fillWithFoundSimpleExpression(pattern.matcher(structuredExpression));
//		}
//	}
//
//	private void fillWithFoundSimpleExpression(Matcher matcher)
//			throws NoSuchExpressionException {
//		if (matcher.find()) {
//			for (int i = 0; i < matcher.groupCount(); i++) {
//				getAddToComplexConditionCB().addItem(
//						ZestUtils.parseSimpleExpression(matcher.group(i)));
//			}
//		}
//	}
//
//	public void init(ZestScript script, ScriptNode parent,
//			List<ScriptNode> children, ZestStatement req, ZestExpression expr,
//			boolean add, boolean surround) {
//		this.script = script;
//		this.add = add;
//		this.parent = parent;
//		this.children = children;
//		this.request = req;
//		this.expression = expr;
//		this.surround = surround;
//		this.removeAllFields();
//		if (add) {
//			this.setTitle(Constant.messages
//					.getString("zest.dialog.condition.add.title"));
//		} else {
//			this.setTitle(Constant.messages
//					.getString("zest.dialog.condition.edit.title"));
//			final String structuredExpression = this.expression.toString();
//			getComplexConditionText().setText(structuredExpression);
//			try {
//				fillAddToComplexConditionComboBox(structuredExpression);
//			} catch (NoSuchExpressionException e) {
//				e.printStackTrace();
//			}
//		}
//		drawComplexConditionDialog();
//	}
//
//	private void drawComplexConditionDialog() {
//		JPanel content = getContentPaneComplexCondition();
//		this.add(content, 0);
//		this.addPadding();
//	}
//
//	@Override
//	public void save() {
//		ZestExpression rootExpression = evaluator
//				.evaluate(getComplexConditionText().getText());
//		expression = rootExpression;
//		ZestElement parentZe = ZestZapUtils.getElement(parent);
//		if (add) {
//			if (parentZe instanceof ZestConditional) {
//				ScriptNode exprNode = extension.addToParent(parent, expression);
//				if (surround) {
//					extension.setCnpNodes(children);
//					extension.setCut(true);
//					extension.pasteToNode(exprNode);
//				}
//			} else {
//				if (request == null) {
//					ScriptNode condNode = extension.addToParent(parent,
//							new ZestConditional(this.expression));
//					if (surround) {
//						extension.setCnpNodes(children);
//						extension.setCut(true);
//						extension.pasteToNode(condNode);
//					}
//				} else {
//					for (ScriptNode child : children) {
//						extension.addAfterRequest(parent, child, request,
//								new ZestConditional(this.expression));
//					}
//				}
//			}
//		} else {
//			for (ScriptNode child : children) {
//				extension.updated(child);
//				extension.display(child, false);
//			}
//		}
//	}
//
//	@Override
//	public String validateFields() {
//		// TODO Auto-generated method stub
//		return null;
//	}
//
//	private enum ConditionType {
//		URL, REGEX, TIME_RESPONSE, STATUS_CODE, EQUALS;
//	}
//
//	class Render implements Runnable {
//		public void run() {
//
//		}
//	}
//
//}
