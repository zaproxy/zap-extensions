/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 * 
 * Copyright 2013 The ZAP Development Team
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
package org.zaproxy.zap.extension.zest.menu;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.zap.extension.zest.ExtensionZest;

public class ZestMenuManager {

	private ZestAddToScriptPopupMenu popupZestAddToMenu = null;
	private ZestCompareResponsePopupMenu compareResponsePopupMenu = null;

	private ZestAddActionPopupMenu popupAddActionMenu = null;
	private ZestAddAssertionPopupMenu popupAddAssertionMenu = null;
	private ZestAddAssignPopupMenu popupAddAssignMenu = null;
	private ZestAddConditionPopupMenu popupAddConditionMenu = null;
	private ZestAddLoopPopupMenu popupAddLoopMenu = null;
	private ZestAddCommentPopupMenu popupAddCommentMenu = null;
	private ZestAddControlPopupMenu popupAddReturnMenu = null;
	
	private ZestSurroundWithPopupMenu popupSurroundWithMenu = null;
	private ZestAddLoopPopupMenu popupAddLoopMenuLevel2 = null;
	
	private ZestPopupZestMove popupZestMoveUp = null;
	private ZestPopupZestMove popupZestMoveDown = null;
	private ZestPopupNodeCopyOrCut popupNodeCopy = null;
	private ZestPopupNodeCopyOrCut popupNodeCut = null;
	private ZestPopupNodePaste popupNodePaste = null;

	private ZestPopupZestDelete popupZestDelete = null;
	private ZestRedactPopupMenu popupRedact = null;
	private ZestParameterizePopupMenu popupParam = null;
	private ZestPasteVariablePopupMenu popupPasteVar = null;
	
	private ExtensionZest extension = null;
	
	public ZestMenuManager(ExtensionZest extension, ExtensionHook extensionHook) {
		this.extension = extension;
		
		extensionHook.getHookMenu().addPopupMenuItem(getPopupZestAddToMenu());
		extensionHook.getHookMenu().addPopupMenuItem(getCompareResponsePopupMenu());

		extensionHook.getHookMenu().addPopupMenuItem(getPopupAddActionMenu());
		extensionHook.getHookMenu().addPopupMenuItem(getPopupAddAssertionMenu());
		extensionHook.getHookMenu().addPopupMenuItem(getPopupAddAssignMenu());
		extensionHook.getHookMenu().addPopupMenuItem(getPopupAddConditionMenu());
		extensionHook.getHookMenu().addPopupMenuItem(getPopupAddLoopMenu());
		extensionHook.getHookMenu().addPopupMenuItem(getPopupAddCommentMenu());
		extensionHook.getHookMenu().addPopupMenuItem(getPopupAddReturnMenu());
		
		extensionHook.getHookMenu().addPopupMenuItem(getPopupSurroundWithMenu());
			
        extensionHook.getHookMenu().addPopupMenuItem(getPopupNodeCut ());
        extensionHook.getHookMenu().addPopupMenuItem(getPopupNodeCopy ());
        extensionHook.getHookMenu().addPopupMenuItem(getPopupNodePaste ());

        extensionHook.getHookMenu().addPopupMenuItem(getPopupZestMoveUp ());
        extensionHook.getHookMenu().addPopupMenuItem(getPopupZestMoveDown ());
        extensionHook.getHookMenu().addPopupMenuItem(getPopupZestDelete ());

        extensionHook.getHookMenu().addPopupMenuItem(getPopupParam ());
        extensionHook.getHookMenu().addPopupMenuItem(getPopupRedact ());
        extensionHook.getHookMenu().addPopupMenuItem(getPopupPasteVar ());

	}

	private ZestAddActionPopupMenu getPopupAddActionMenu() {
		if (popupAddActionMenu == null) {
			popupAddActionMenu= new ZestAddActionPopupMenu(this.extension);
		}
		return popupAddActionMenu;
	}

	private ZestAddAssertionPopupMenu getPopupAddAssertionMenu() {
		if (popupAddAssertionMenu == null) {
			popupAddAssertionMenu= new ZestAddAssertionPopupMenu(this.extension);
		}
		return popupAddAssertionMenu;
	}

	private ZestAddAssignPopupMenu getPopupAddAssignMenu() {
		if (popupAddAssignMenu == null) {
			popupAddAssignMenu= new ZestAddAssignPopupMenu(this.extension);
		}
		return popupAddAssignMenu;
	}

	private ZestAddConditionPopupMenu getPopupAddConditionMenu() {
		if (popupAddConditionMenu == null) {
			popupAddConditionMenu= new ZestAddConditionPopupMenu(this.extension);
		}
		return popupAddConditionMenu;
	}
	
	protected ZestAddLoopPopupMenu getPopupAddLoopMenu() {
		if (popupAddLoopMenu == null) {
			popupAddLoopMenu= new ZestAddLoopPopupMenu(this.extension);
		}
		return popupAddLoopMenu;
	}
	
	protected ZestAddLoopPopupMenu getPopupAddLoopMenuLevel2() {
		if (popupAddLoopMenuLevel2 == null) {
			popupAddLoopMenuLevel2= new ZestAddLoopPopupMenu(this.extension);
		}
		return popupAddLoopMenuLevel2;
	}
	
	private ZestSurroundWithPopupMenu getPopupSurroundWithMenu() {
		if (popupSurroundWithMenu== null) {
			popupSurroundWithMenu= new ZestSurroundWithPopupMenu(this.extension);
		}
		return popupSurroundWithMenu;
	}
//	private List<ExtensionPopupMenuItem> getSurroundOptions(){// TODO maybe store as a field.
//		LinkedList<ExtensionPopupMenuItem> options=new LinkedList<>();
//		options.add(getPopupAddConditionMenu());
//		options.add(getPopupAddConditionMenu());
//		return options;
//	}

	private ZestAddToScriptPopupMenu getPopupZestAddToMenu() {
		if (popupZestAddToMenu == null) {
			popupZestAddToMenu = new ZestAddToScriptPopupMenu(this.extension);
		}
		return popupZestAddToMenu;
	}

	private ZestAddCommentPopupMenu getPopupAddCommentMenu() {
		if (popupAddCommentMenu == null) {
			popupAddCommentMenu = new ZestAddCommentPopupMenu(this.extension);
		}
		return popupAddCommentMenu;
	}

	private ZestAddControlPopupMenu getPopupAddReturnMenu() {
		if (popupAddReturnMenu == null) {
			popupAddReturnMenu = new ZestAddControlPopupMenu(this.extension);
		}
		return popupAddReturnMenu;
	}

	private ZestCompareResponsePopupMenu getCompareResponsePopupMenu() {
		if (compareResponsePopupMenu == null) {
			compareResponsePopupMenu = new ZestCompareResponsePopupMenu(this.extension);
		}
		return compareResponsePopupMenu;
	}
	
	private ZestPopupZestDelete getPopupZestDelete () {
		if (popupZestDelete == null) {
			popupZestDelete = new ZestPopupZestDelete(this.extension); 
		}
		return popupZestDelete;
	}

	private ZestPopupZestMove getPopupZestMoveUp () {
		if (popupZestMoveUp == null) {
			popupZestMoveUp = new ZestPopupZestMove(this.extension, true); 
		}
		return popupZestMoveUp;
	}

	private ZestPopupZestMove getPopupZestMoveDown () {
		if (popupZestMoveDown == null) {
			popupZestMoveDown = new ZestPopupZestMove(this.extension, false); 
		}
		return popupZestMoveDown;
	}

	private ZestPopupNodeCopyOrCut getPopupNodeCopy () {
		if (popupNodeCopy == null) {
			popupNodeCopy = new ZestPopupNodeCopyOrCut(this.extension, false);
		}
		return popupNodeCopy;
	}
	
	private ZestPopupNodeCopyOrCut getPopupNodeCut () {
		if (popupNodeCut == null) {
			popupNodeCut = new ZestPopupNodeCopyOrCut(this.extension, true);
		}
		return popupNodeCut;
	}
	
	private ZestPopupNodePaste getPopupNodePaste () {
		if (popupNodePaste == null) {
			popupNodePaste = new ZestPopupNodePaste(this.extension);
		}
		return popupNodePaste;
	}

	private ZestRedactPopupMenu getPopupRedact() {
		if (popupRedact == null) {
			popupRedact = new ZestRedactPopupMenu(this.extension, Constant.messages.getString("zest.redact.popup"));
		}
		return popupRedact;
	}

	private ZestParameterizePopupMenu getPopupParam() {
		if (popupParam == null) {
			popupParam = new ZestParameterizePopupMenu(this.extension, Constant.messages.getString("zest.parameterize.popup"));
		}
		return popupParam;
	}

	private ZestPasteVariablePopupMenu getPopupPasteVar () {
		if (popupPasteVar== null) {
			popupPasteVar = new ZestPasteVariablePopupMenu(this.extension);
		}
		return popupPasteVar;
	}


}
