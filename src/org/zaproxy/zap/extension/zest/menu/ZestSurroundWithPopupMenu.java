/**
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 * 
 * @author Alessandro Secco: seccoale@gmail.com
 */
package org.zaproxy.zap.extension.zest.menu;

import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.mozilla.zest.core.v1.ZestConditional;
import org.mozilla.zest.core.v1.ZestElement;
import org.mozilla.zest.core.v1.ZestLoop;
import org.mozilla.zest.core.v1.ZestLoopFile;
import org.mozilla.zest.core.v1.ZestLoopInteger;
import org.mozilla.zest.core.v1.ZestLoopString;
import org.mozilla.zest.core.v1.ZestStatement;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionPopupMenuItem;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zap.extension.zest.ExtensionZest;
import org.zaproxy.zap.extension.zest.ZestZapUtils;

public class ZestSurroundWithPopupMenu extends ExtensionPopupMenuItem {
	private static final long serialVersionUID = -5847208243296422433L;
	private ExtensionZest extension;
	private List<ExtensionPopupMenuItem> subMenus = new ArrayList<>();

	/**
	 * This method initializes
	 * 
	 */
	public ZestSurroundWithPopupMenu(ExtensionZest extension) {
		super("SurroundWithX");
		this.extension = extension;
	}

	/**/
	@Override
	public String getParentMenuName() {
		return Constant.messages.getString("zest.surround.with.popup");
	}

	@Override
	public boolean isSubMenu() {
		return true;
	}

	@Override
	public boolean isDummyItem() {
		return true;
	}

	public boolean isEnableForComponent(Component invoker) {
		for (ExtensionPopupMenuItem menu : subMenus) {
			View.getSingleton().getPopupMenu().removeMenu(menu);
		}
		subMenus.clear();
		// Remove previous submenus
		if (extension.isScriptTree(invoker)) {
			List<ScriptNode> selectedNodes = extension.getSelectedZestNodes();
			if (selectedNodes == null || selectedNodes.isEmpty()) {
				return false;
			}
			ScriptNode parent = selectedNodes.get(0).getParent();
			if (parent == null
					|| !(ZestZapUtils.getElement(parent) instanceof ZestStatement)) {
				return false;
			}
			reCreateSubMenu(parent, selectedNodes);
		}
		return false;
	}

	private void reCreateSubMenu(ScriptNode parent, List<ScriptNode> children) {
		createPopupAddActionMenu(parent, children, new ZestLoopString());
		try {
			createPopupAddActionMenu(parent, children, new ZestLoopFile());
		} catch (IOException e) {
			e.printStackTrace();
		}
		createPopupAddActionMenu(parent, children, new ZestLoopInteger());
//		createPopupAddActionMenu(parent, children, new ZestConditional());
	}

	private void createPopupAddActionMenu(final ScriptNode parent,
			final List<ScriptNode> children, final ZestElement za) {
		ZestPopupMenu menu;
		if(za instanceof ZestConditional){
			menu = new ZestPopupMenu(
					Constant.messages.getString("zest.surround.with.popup"),
					ZestZapUtils.toUiString(za, false));
		}
		else{
		menu = new ZestPopupMenu(
				Constant.messages.getString("zest.surround.with.popup"),
				ZestZapUtils.toUiString(za, false));
		}
		if (za instanceof ZestLoop<?>) {
			menu.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent e) {
					extension.getDialogManager().showZestLoopDialog(parent,
							children, null, (ZestLoop<?>) za, true, true);
				}
			});
		} else if (za instanceof ZestConditional){
			menu.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent e) {
					extension.getDialogManager().showZestConditionalDialog(parent,
							children, null, (ZestConditional) za, true, true);
				}
			});
		}
		menu.setMenuIndex(this.getMenuIndex());
		View.getSingleton().getPopupMenu().addMenu(menu);
		this.subMenus.add(menu);
	}

	@Override
	public boolean isSafe() {
		return true;
	}

}
