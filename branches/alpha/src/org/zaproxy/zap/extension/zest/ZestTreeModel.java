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

import java.util.Enumeration;

import javax.swing.tree.DefaultTreeModel;

import org.apache.log4j.Logger;
import org.mozilla.zest.core.v1.ZestAction;
import org.mozilla.zest.core.v1.ZestAssertion;
import org.mozilla.zest.core.v1.ZestConditional;
import org.mozilla.zest.core.v1.ZestElement;
import org.mozilla.zest.core.v1.ZestRequest;
import org.mozilla.zest.core.v1.ZestScript;
import org.mozilla.zest.core.v1.ZestStatement;
import org.mozilla.zest.core.v1.ZestTransformation;

/**
 *
 * To change the template for this generated type comment go to
 * Window - Preferences - Java - Code Generation - Code and Comments
 */
class ZestTreeModel extends DefaultTreeModel {

	private static final long serialVersionUID = 1L;

	private static final Logger logger = Logger.getLogger(ZestTreeModel.class);

    ZestTreeModel() {
        super(new ZestNode());
    }

	public ZestNode addScript(ZestScriptWrapper script) {
		// TODO Check for duplicate names (?)
		logger.debug("addScript " + script.getTitle());
		ZestNode zestNode = new ZestNode(script);
		((ZestNode)this.root).add(zestNode);
		
		// Load "Common Tests" - these are applied to each request
		ZestNode ctNode = new ZestNode(new ZestCommonTestsElement());
		zestNode.add(ctNode);
		for (ZestStatement stmt :script.getCommonTests()) {
			this.addToNode(ctNode, stmt);
		}
		
		for (ZestStatement stmt :script.getStatements()) {
			this.addToNode(zestNode, stmt);
		}
		
		this.nodeStructureChanged(this.root);
		return zestNode;
	}

	public void update(ZestScriptWrapper script) {
		@SuppressWarnings("unchecked")
		Enumeration<ZestNode> en = this.root.children();
		while (en.hasMoreElements()) {
			ZestNode zn = en.nextElement();
			if (script.equals(zn.getZestElement())) {
				// Go through requests in case prefix changed
				for (int i=0; i < zn.getChildCount(); i++) {
					ZestNode child = (ZestNode)zn.getChildAt(i);
					child.nameChanged();
				}
				this.nodeStructureChanged(zn);

				break;
			}
		}
		this.nodeStructureChanged(this.root);
	}
    
	public void removeScript(ZestScriptWrapper script) {
		@SuppressWarnings("unchecked")
		Enumeration<ZestNode> en = this.root.children();
		while (en.hasMoreElements()) {
			ZestNode zn = en.nextElement();
			if (script.equals(zn.getZestElement())) {
				((ZestNode)root).remove(zn);
				break;
			}
		}
		this.nodeStructureChanged(this.root);
	}
    
	public ZestNode addToNode(ZestNode node, ZestRequest req) {
		ZestNode zestNode = new ZestNode(req);
		node.add(zestNode);
		for (ZestTransformation zt : req.getTransformations()) {
			this.addToNode(zestNode, zt);
		}
		for (ZestAssertion za : req.getAssertions()) {
			this.addToNode(zestNode, za);
		}
		
		this.nodeStructureChanged(node);
		return zestNode;
	}
    
	public ZestNode addToNode(ZestNode parent, ZestElement za) {
		logger.debug("addToNode " + parent.getNodeName() + " " + za.getElementType());

		ZestNode zestNode = new ZestNode(za);
		if (parent.getZestElement() instanceof ZestRequest) {
			int childIndex = 0;
			for (; childIndex < parent.getChildCount(); childIndex++) {
				ZestNode child = (ZestNode) parent.getChildAt(childIndex);
				/* Order:
				 *  Transformations
				 *  Assertations
				 */
				
				if (child.getZestElement() instanceof ZestTransformation) {
					// These should always be first
					continue;
				} else if (child.getZestElement() instanceof ZestAssertion) {
					if (za instanceof ZestTransformation) {
						// Transformations come before Assertions
						break;
					}
				}
			}
			parent.insert(zestNode, childIndex);
			
		} else if (za instanceof ZestRequest) {
			ZestRequest zr = (ZestRequest)za;
			parent.add(zestNode);
			
			for (ZestTransformation zt : zr.getTransformations()) {
				this.addToNode(zestNode, zt);
			}
			for (ZestAssertion zt : zr.getAssertions()) {
				this.addToNode(zestNode, zt);
			}
			
		} else if (za instanceof ZestConditional) {
			ZestConditional zc = (ZestConditional)za;

			parent.add(zestNode);
			for (ZestStatement stmt : zc.getIfStatements()) {
				this.addToNode(zestNode, stmt);
			}

			// 'Shadow' node for else path
			ZestNode elseNode = new ZestNode(za, true);
			parent.add(elseNode);
			for (ZestStatement stmt : zc.getElseStatements()) {
				this.addToNode(elseNode, stmt);
			}
			
		} else {
			parent.add(zestNode);
		}
		this.nodeStructureChanged(parent);
		return zestNode;
	}

	public ZestNode addAfterNode(ZestNode node, ZestStatement stmt) {
		logger.debug("addAfterNode " + node.getNodeName() + " " + stmt.getElementType());
		ZestNode zestNode = new ZestNode(stmt);
		ZestNode parent = node.getParent();
		if (node.getZestElement() instanceof ZestRequest) {
			parent.insert(zestNode, parent.getIndex(node)+1);
		}
		if (stmt instanceof ZestConditional) {
			// 'Shadow' node for else path
			ZestNode elseNode = new ZestNode(stmt, true);
			parent.insert(elseNode, parent.getIndex(zestNode)+1);
		}
		this.nodeStructureChanged(parent);
		return zestNode;
	}

	public void delete(ZestNode node) {
		ZestNode parent = node.getParent();
		
		if (parent.getZestElement() == null) {
			logger.error("delete: Parent user object null: " + parent.toString());
			return;
		}
		if (node.getZestElement() == null) {
			logger.error("delete: Child user object null: " + node.toString());
			return;
		}
		
		if (parent.getChildAfter(node) != null && ((ZestNode)parent.getChildAfter(node)).isShadow()) {
			// Remove shadow node
			parent.remove((ZestNode)parent.getChildAfter(node));
		}
		parent.remove(node);
		

		if (parent.isRoot()) {
			if ((node.getZestElement() instanceof ZestScript)) {
				logger.error("delete: unexpected child of root node: " + node.getZestElement().getClass().getCanonicalName());
			}
		} else if (parent.getZestElement() instanceof ZestScript) {
			if (node.getZestElement() instanceof ZestStatement) {
				((ZestScript)parent.getZestElement()).remove((ZestStatement)node.getZestElement());
			} else {
				logger.error("delete: unexpected child of script node: " + node.getZestElement().getClass().getCanonicalName());
			}
		} else if (parent.getZestElement() instanceof ZestConditional) {
			ZestConditional zc = (ZestConditional)parent.getZestElement();
			if (parent.isShadow()) {
				zc.removeElse((ZestStatement)node.getZestElement());
			} else {
				zc.removeIf((ZestStatement)node.getZestElement());
			}
		} else if (parent.getZestElement() instanceof ZestRequest) {
			if (node.getZestElement() instanceof ZestAssertion) {
				((ZestRequest)parent.getZestElement()).removeAssertion((ZestAssertion)node.getZestElement());
			} else if (node.getZestElement() instanceof ZestTransformation) {
				((ZestRequest)parent.getZestElement()).removeTransformation((ZestTransformation)node.getZestElement());
			} else {
				logger.error("delete: unexpected child of request node: " + node.getZestElement().getClass().getCanonicalName());
			}
		} else if (parent.getZestElement() instanceof ZestAction) {
			logger.error("delete: unexpected child of request node: " + node.getZestElement().getClass().getCanonicalName());
		} else {
			logger.error("delete: unknown nodes: " + node.toString() + " " + parent.toString());
			logger.error("Parent user object: " + parent.getZestElement().getClass().getCanonicalName());
			logger.error("Child user object: " + node.getZestElement().getClass().getCanonicalName());
		}
		
		this.nodeStructureChanged(parent);
	}

	private ZestNode getZestNode(ZestNode parent, ZestElement element) {
		for (int i=0; i < parent.getChildCount(); i++) {
			ZestNode node = (ZestNode)parent.getChildAt(i);
			if (node != null && node.getZestElement() != null) {
				if ((node.getZestElement()).equals(element)) {
					return node;
				}
			}
			node = this.getZestNode(node, element);
			if (node != null) {
				return node;
			}
		}
		return null;
		
	}
	public ZestNode getZestNode(ZestElement element) {
		if (element == null) {
			return null;
		}
		return getZestNode((ZestNode) this.root, element);
	}

	public void update(ZestElement parent, ZestElement child) {
		ZestNode node = this.getZestNode(parent);
		if (node != null) {
			node = this.getZestNode(node, child);
			if (node != null) {
				node.nameChanged();
				this.nodeChanged(node);
			} else {
				logger.error("Failed to find child in tree " + ZestZapUtils.toUiString(child));
			}
		} else {
			logger.error("Failed to find parent in tree " + ZestZapUtils.toUiString(parent));
		}
		
	}

	public void update(ZestScript script, ZestStatement request) {
		ZestNode node = this.getZestNode(request);
		if (node != null) {
			node.nameChanged();
			this.nodeChanged(node);
		} else {
			logger.error("Failed to find ZestElement in tree " + ZestZapUtils.toUiString(request));
		}
		
	}

	public void switchNodes(ZestNode node1, ZestNode node2) {
		if (! node1.getParent().equals(node2.getParent())) {
			logger.error("Nodes have different parents " + node1.getNodeName() + " " + node2.getNodeName());
		} else {
			ZestNode parent = node1.getParent();
			int i1 = parent.getIndex(node1);
			int i2 = parent.getIndex(node2);
			
			ZestNode shadow1 = null;
			ZestNode shadow2 = null;
			
			if (parent.getChildAfter(node1) != null && ((ZestNode)parent.getChildAfter(node1)).isShadow()) {
				shadow1 = (ZestNode)parent.getChildAfter(node1);
			}
			if (parent.getChildAfter(node2) != null && ((ZestNode)parent.getChildAfter(node2)).isShadow()) {
				shadow2 = (ZestNode)parent.getChildAfter(node2);
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
				parent.insert(shadow1, parent.getIndex(node1)+1);
			}
			if (shadow2 != null) {
				parent.remove(shadow2);
				parent.insert(shadow2, parent.getIndex(node2)+1);
			}
			
			this.nodeStructureChanged(parent);
		}
		
	}
}
