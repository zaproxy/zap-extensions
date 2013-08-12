/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 * 
 * Copyright 2013 The ZAP Development team
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
package org.zaproxy.zap.extension.zest;

import java.util.List;

import org.apache.log4j.Logger;
import org.mozilla.zest.core.v1.ZestAction;
import org.mozilla.zest.core.v1.ZestAssertion;
import org.mozilla.zest.core.v1.ZestConditional;
import org.mozilla.zest.core.v1.ZestElement;
import org.mozilla.zest.core.v1.ZestLoop;
import org.mozilla.zest.core.v1.ZestRequest;
import org.mozilla.zest.core.v1.ZestScript;
import org.mozilla.zest.core.v1.ZestStatement;
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zap.extension.script.ScriptTreeModel;

/**
 * 
 * To change the template for this generated type comment go to Window -
 * Preferences - Java - Code Generation - Code and Comments
 */
public class ZestTreeModel {

	private static final Logger logger = Logger.getLogger(ZestTreeModel.class);

	private ScriptTreeModel model;

	public ZestTreeModel(ScriptTreeModel model) {
		this.model = model;
	}

	public void addScript(ScriptNode parent, ZestScriptWrapper script) {
		logger.debug("addScript " + script.getName());
		if (script.getZestScript().getStatements() != null) {
			for (ZestStatement stmt : script.getZestScript().getStatements()) {
				this.addToNode(parent, stmt);
			}
		}

		model.nodeStructureChanged(parent);
	}

	private ScriptNode getZestNode(ZestElement ze) {
		return this.getZestNode(ze, false);
	}

	private ScriptNode getZestNode(ZestElement ze, boolean shadow) {
		ScriptNode zestNode = new ScriptNode(ZestZapUtils.toUiString(ze, true,
				shadow));
		zestNode.setUserObject(new ZestElementWrapper(ze, shadow));
		return zestNode;
	}

	public ScriptNode addToNode(ScriptNode parent, ZestElement za) {
		logger.debug("addToNode " + parent.getNodeName() + " "
				+ za.getElementType());

		ScriptNode zestNode = this.getZestNode(za);
		ZestElement parentZe = ZestZapUtils.getElement(parent);

		if (parentZe instanceof ZestRequest) {
			parent.add(zestNode);
		} else if (za instanceof ZestRequest) {
			ZestRequest zr = (ZestRequest) za;
			parent.add(zestNode);

			for (ZestAssertion zt : zr.getAssertions()) {
				this.addToNode(zestNode, zt);
			}

		} else if (za instanceof ZestConditional) {
			ZestConditional zc = (ZestConditional) za;

			parent.add(zestNode);
			for (ZestStatement stmt : zc.getIfStatements()) {
				this.addToNode(zestNode, stmt);
			}

			// 'Shadow' node for else path
			ScriptNode elseNode = this.getZestNode(za, true);

			parent.add(elseNode);
			for (ZestStatement stmt : zc.getElseStatements()) {
				this.addToNode(elseNode, stmt);
			}

		} else {
			parent.add(zestNode);
		}
		model.nodeStructureChanged(parent);
		return zestNode;
	}

	public ScriptNode addAfterNode(ScriptNode node, ZestStatement stmt) {
		logger.debug("addAfterNode " + node.getNodeName() + " "
				+ stmt.getElementType());
		ScriptNode zestNode = this.getZestNode(stmt);
		ScriptNode parent = node.getParent();
		if (ZestZapUtils.getElement(node) instanceof ZestRequest) {
			parent.insert(zestNode, parent.getIndex(node) + 1);
		}
		if (stmt instanceof ZestConditional) {
			// 'Shadow' node for else path
			ScriptNode elseNode = this.getZestNode(stmt, true);
			parent.insert(elseNode, parent.getIndex(zestNode) + 1);
		}
		model.nodeStructureChanged(parent);
		return zestNode;
	}

	public void delete(ScriptNode node) {
		ScriptNode parent = node.getParent();
		ZestElement parentZe = ZestZapUtils.getElement(parent);
		ZestElement childZe = ZestZapUtils.getElement(node);

		if (parentZe == null) {
			logger.error("delete: Parent user object null: "
					+ parent.toString());
			return;
		}
		if (childZe == null) {
			logger.error("delete: Child user object null: " + node.toString());
			return;
		}
		if (parent.getChildAfter(node) != null
				&& (ZestZapUtils.isShadow((ScriptNode) parent
						.getChildAfter(node)))) {
			// Remove shadow node
			parent.remove((ScriptNode) parent.getChildAfter(node));
		}
		parent.remove(node);

		if (parent.getParent().isRoot()) {
			if ((childZe instanceof ZestScript)) {
				logger.error("delete: unexpected child of root node: "
						+ childZe.getClass().getCanonicalName());
			}
		} else if (parentZe instanceof ZestScript) {
			if (childZe instanceof ZestStatement) {
				((ZestScript) parentZe).remove((ZestStatement) childZe);
			} else {
				logger.error("delete: unexpected child of script node: "
						+ childZe.getClass().getCanonicalName());
			}
		} else if (parentZe instanceof ZestConditional) {
			ZestConditional zc = (ZestConditional) parentZe;
			if (ZestZapUtils.isShadow(parent)) {
				zc.removeElse((ZestStatement) childZe);
			} else {
				zc.removeIf((ZestStatement) childZe);
			}
		} else if (parentZe instanceof ZestLoop<?>) {
			ZestLoop<?> zl = (ZestLoop<?>) parentZe;
			zl.getStatements().remove((ZestStatement) childZe);
		} else if (parentZe instanceof ZestRequest) {
			 if (childZe instanceof ZestAssertion) {
                 ((ZestRequest)parentZe).removeAssertion((ZestAssertion)childZe);
         } else {
                 logger.error("delete: unexpected child of request node: " + childZe.getClass().getCanonicalName());
         }
		} else if (parentZe instanceof ZestAction) {
			logger.error("delete: unexpected child of request node: "
					+ childZe.getClass().getCanonicalName());
		} else {
			logger.error("delete: unknown nodes: " + node.toString() + " "
					+ parent.toString());
			logger.error("Parent user object: "
					+ parentZe.getClass().getCanonicalName());
			logger.error("Child user object: "
					+ childZe.getClass().getCanonicalName());
		}

		model.nodeStructureChanged(parent);
	}
	
	public void surroundWith(List<ScriptNode> nodes, ScriptNode parent){
		//TODO
	}

	public ZestScriptWrapper getScriptWrapper(ScriptNode node) {
		if (node == null || node.getUserObject() == null) {
			return null;
		}
		if (node.getUserObject() instanceof ZestScriptWrapper) {
			return (ZestScriptWrapper) node.getUserObject();
		}
		return this.getScriptWrapper((ScriptNode) node.getParent());
	}

	public ScriptNode getScriptWrapperNode(ScriptNode node) {
		if (node == null || node.getUserObject() == null) {
			return null;
		}
		if (node.getUserObject() instanceof ZestScriptWrapper) {
			return node;
		}
		return this.getScriptWrapperNode((ScriptNode) node.getParent());
	}

	public void update(ScriptNode node) {
		logger.debug("Update node=" + node.getNodeName());
		ZestElement ze = ZestZapUtils.getElement(node);
		node.setNodeName(ZestZapUtils.toUiString(ze, true,
				ZestZapUtils.isShadow(node)));
		model.nodeChanged(node);
		model.nodeStructureChanged(node.getParent());
	}

	/**
	 * Switch the 2 specified nodes - they must have the same parent and be
	 * adjacent
	 * 
	 * @param node1
	 * @param node2
	 */
	public void switchNodes(ScriptNode node1, ScriptNode node2) {
		if (!node1.getParent().equals(node2.getParent())) {
			logger.error("Nodes have different parents " + node1.getNodeName()
					+ " " + node2.getNodeName());
		} else {
			ScriptNode parent = node1.getParent();
			int i1 = parent.getIndex(node1);
			int i2 = parent.getIndex(node2);

			ScriptNode shadow1 = null;
			ScriptNode shadow2 = null;

			if (parent.getChildAfter(node1) != null
					&& ZestZapUtils.isShadow((ScriptNode) parent
							.getChildAfter(node1))) {
				shadow1 = (ScriptNode) parent.getChildAfter(node1);
			}
			if (parent.getChildAfter(node2) != null
					&& ZestZapUtils.isShadow((ScriptNode) parent
							.getChildAfter(node2))) {
				shadow2 = (ScriptNode) parent.getChildAfter(node2);
			}

			parent.remove(node1);
			parent.remove(node2);

			if (i1 > i2) {
				parent.insert(node1, i2);
				parent.insert(node2, i1);
			} else {
				parent.insert(node2, i1);
				parent.insert(node1, i2);
			}
			if (shadow1 != null) {
				parent.remove(shadow1);
				parent.insert(shadow1, parent.getIndex(node1) + 1);
			}
			if (shadow2 != null) {
				parent.remove(shadow2);
				parent.insert(shadow2, parent.getIndex(node2) + 1);
			}

			model.nodeStructureChanged(parent);
		}
	}

}
