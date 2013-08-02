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

import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.zap.extension.zest.ExtensionZest;

public class ZestMenuManager {

	private ZestAddToScriptPopupMenu popupZestAddToMenu = null;
	private ZestCompareResponsePopupMenu compareResponsePopupMenu = null;

	private ZestAddActionPopupMenu popupAddActionMenu = null;
	private ZestAddAssertionPopupMenu popupAddAssertionMenu = null;
	private ZestAddConditionPopupMenu popupAddConditionMenu = null;
	private ZestPopupZestMove popupZestMoveUp = null;
	private ZestPopupZestMove popupZestMoveDown = null;
	private ZestPopupNodeCopyOrCut popupNodeCopy = null;
	private ZestPopupNodeCopyOrCut popupNodeCut = null;
	private ZestPopupNodePaste popupNodePaste = null;

	private ZestPopupZestDelete popupZestDelete = null;

	private ExtensionZest extension = null;
	
	public ZestMenuManager(ExtensionZest extension, ExtensionHook extensionHook) {
		this.extension = extension;
		
		extensionHook.getHookMenu().addPopupMenuItem(getPopupZestAddToMenu());
		extensionHook.getHookMenu().addPopupMenuItem(getCompareResponsePopupMenu());

		extensionHook.getHookMenu().addPopupMenuItem(getPopupAddActionMenu());
		extensionHook.getHookMenu().addPopupMenuItem(getPopupAddAssertionMenu());
		extensionHook.getHookMenu().addPopupMenuItem(getPopupAddConditionMenu());
	
        extensionHook.getHookMenu().addPopupMenuItem(getPopupNodeCut ());
        extensionHook.getHookMenu().addPopupMenuItem(getPopupNodeCopy ());
        extensionHook.getHookMenu().addPopupMenuItem(getPopupNodePaste ());

        extensionHook.getHookMenu().addPopupMenuItem(getPopupZestMoveUp ());
        extensionHook.getHookMenu().addPopupMenuItem(getPopupZestMoveDown ());
        extensionHook.getHookMenu().addPopupMenuItem(getPopupZestDelete ());

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

	private ZestAddConditionPopupMenu getPopupAddConditionMenu() {
		if (popupAddConditionMenu == null) {
			popupAddConditionMenu= new ZestAddConditionPopupMenu(this.extension);
		}
		return popupAddConditionMenu;
	}

	private ZestAddToScriptPopupMenu getPopupZestAddToMenu() {
		if (popupZestAddToMenu == null) {
			popupZestAddToMenu = new ZestAddToScriptPopupMenu(this.extension);
		}
		return popupZestAddToMenu;
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

}
