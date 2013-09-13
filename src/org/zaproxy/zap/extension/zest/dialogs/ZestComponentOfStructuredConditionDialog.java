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
//
//import org.zaproxy.zap.extension.zest.ExtensionZest;
//
//public class ZestComponentOfStructuredConditionDialog extends
//		ZestExpressionDialog {
//	private static final long serialVersionUID = 790679073827365883L;
//	
//	private final ZestComplexConditionDialog owner;
//	
//	public ZestComponentOfStructuredConditionDialog(ExtensionZest ext,
//			ZestComplexConditionDialog owner, Dimension dim) {
//		super(ext, owner, dim);
//		this.owner=owner;
//	}
//	@Override
//	public void save() {
//		super.save();
//		owner.addSimpleCondition(getCondition());
//		owner.enableEditSimpleConditionBTN(true);
//	}
// }
