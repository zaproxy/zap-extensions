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
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.zest;

import org.apache.log4j.Logger;
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zap.extension.script.ScriptTreeModel;
import org.zaproxy.zest.core.v1.ZestAction;
import org.zaproxy.zest.core.v1.ZestAssertion;
import org.zaproxy.zest.core.v1.ZestConditional;
import org.zaproxy.zest.core.v1.ZestElement;
import org.zaproxy.zest.core.v1.ZestExpression;
import org.zaproxy.zest.core.v1.ZestExpressionElement;
import org.zaproxy.zest.core.v1.ZestLoop;
import org.zaproxy.zest.core.v1.ZestRequest;
import org.zaproxy.zest.core.v1.ZestScript;
import org.zaproxy.zest.core.v1.ZestStatement;
import org.zaproxy.zest.core.v1.ZestStructuredExpression;

/**
 * To change the template for this generated type comment go to Window - Preferences - Java - Code
 * Generation - Code and Comments
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
        return this.getZestNode(ze, 0);
    }

    private ScriptNode getZestNode(ZestElement ze, int shadowLevel) {
        ScriptNode zestNode = new ScriptNode(ZestZapUtils.toUiString(ze, true, shadowLevel));
        zestNode.setUserObject(new ZestElementWrapper(ze, shadowLevel));
        return zestNode;
    }

    public ScriptNode addToNode(ScriptNode parent, ZestElement za) {
        logger.debug("addToNode " + parent.getNodeName() + " " + za.getElementType());
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
            this.addToNode(zestNode, (ZestElement) zc.getRootExpression());

            // 'Shadow' 1 node for then path
            ScriptNode ifNode = this.getZestNode(za, 1);

            parent.add(ifNode);
            for (int i = 0; i < zc.getIfStatements().size(); i++) {
                this.addToNode(ifNode, zc.getIfStatement(i));
            }

            // 'Shadow' 2 node for else path
            ScriptNode elseNode = this.getZestNode(za, 2);

            parent.add(elseNode);
            for (int i = 0; i < zc.getElseStatements().size(); i++) {
                this.addToNode(elseNode, zc.getElseStatement(i));
            }

        } else if (za instanceof ZestLoop<?>) {
            ZestLoop<?> zl = (ZestLoop<?>) za;
            parent.add(zestNode);
            for (ZestStatement stmt : zl.getStatements()) {
                this.addToNode(zestNode, stmt);
            }
        } else if (za instanceof ZestExpression) {
            ZestExpression ze = (ZestExpression) za;
            zestNode = this.getZestNode(ze);
            parent.add(zestNode);
            if (ze instanceof ZestStructuredExpression) {
                for (ZestExpressionElement childCond :
                        ((ZestStructuredExpression) ze).getChildrenCondition()) {
                    this.addToNode(zestNode, (ZestExpression) childCond);
                }
            }
        } else {
            logger.debug("added a non container element " + za.getElementType());
            parent.add(zestNode);
        }
        model.nodeStructureChanged(parent);
        return zestNode;
    }

    public ScriptNode addToNodeAt(ScriptNode parent, ZestElement za, int index) {
        logger.debug(
                "addToNode " + parent.getNodeName() + " " + za.getElementType() + " at " + index);
        ScriptNode zestNode = this.getZestNode(za);
        ZestElement parentZe = ZestZapUtils.getElement(parent);

        if (za instanceof ZestExpression && parentZe instanceof ZestStructuredExpression) {
            ZestExpression exp = (ZestExpression) za;
            ZestStructuredExpression parentExp = (ZestStructuredExpression) parentZe;
            parentExp.addChildCondition(exp, index);
            parent.insert(parent, index);
            if (exp instanceof ZestStructuredExpression) {
                for (ZestExpressionElement subExp :
                        ((ZestStructuredExpression) exp).getChildrenCondition()) {
                    this.addToNode(zestNode, (ZestElement) subExp);
                }
            }

        } else {
            parent.insert(zestNode, index);
        }

        if (za instanceof ZestRequest) {
            ZestRequest zr = (ZestRequest) za;

            for (ZestAssertion zt : zr.getAssertions()) {
                this.addToNode(zestNode, zt);
            }

        } else if (za instanceof ZestConditional) {
            ZestConditional zc = (ZestConditional) za;
            this.addToNode(zestNode, (ZestElement) zc.getRootExpression());

            ScriptNode ifNode = this.getZestNode(za, 1);

            parent.insert(ifNode, index + 1);
            for (ZestStatement stmt : zc.getIfStatements()) {
                this.addToNode(ifNode, stmt);
            }

            // 'Shadow' node for else path
            ScriptNode elseNode = this.getZestNode(za, 2);

            parent.insert(elseNode, index + 2);
            for (ZestStatement stmt : zc.getElseStatements()) {
                this.addToNode(elseNode, stmt);
            }

        } else if (za instanceof ZestLoop<?>) {
            ZestLoop<?> zl = (ZestLoop<?>) za;
            for (ZestStatement stmt : zl.getStatements()) {
                this.addToNode(zestNode, stmt);
            }
        } else if (za instanceof ZestExpression && parentZe instanceof ZestStructuredExpression) {
            ZestExpression exp = (ZestExpression) za;
            ZestStructuredExpression parentExp = (ZestStructuredExpression) parentZe;
            parentExp.addChildCondition(exp, index);
            if (exp instanceof ZestStructuredExpression) {
                for (ZestExpressionElement subExp :
                        ((ZestStructuredExpression) exp).getChildrenCondition()) {
                    this.addToNode(zestNode, (ZestElement) subExp);
                }
            }
        }
        model.nodeStructureChanged(parent);
        return zestNode;
    }

    public ScriptNode addAfterNode(ScriptNode parent, ScriptNode existingNode, ZestStatement stmt) {
        logger.debug("addAfterNode " + existingNode.getNodeName() + " " + stmt.getElementType());

        return this.addToNodeAt(parent, stmt, parent.getIndex(existingNode) + 1);
    }

    public ScriptNode addBeforeNode(
            ScriptNode parent, ScriptNode existingNode, ZestStatement stmt) {
        logger.debug("addBeforeNode " + existingNode.getNodeName() + " " + stmt.getElementType());

        return this.addToNodeAt(parent, stmt, parent.getIndex(existingNode));
    }

    public void delete(ScriptNode node) {
        if (node == null) {
            return;
        }
        ScriptNode parent = node.getParent();
        if (parent == null) {
            return;
        }
        ZestElement parentZe = ZestZapUtils.getElement(parent);
        ZestElement childZe = ZestZapUtils.getElement(node);

        if (parentZe == null) {
            logger.error("delete: Parent user object null: " + node.toString());
            return;
        }
        if (childZe == null) {
            logger.error("delete: Child user object null: " + node.toString());
            return;
        }
        if (ZestZapUtils.getElement(node) instanceof ZestConditional) {
            if (ZestZapUtils.getShadowLevel(node) == 0) {
                // Remove else node
                parent.remove((ScriptNode) parent.getChildAfter(parent.getChildAfter(node)));
                // Remove then node
                parent.remove((ScriptNode) parent.getChildAfter(node));
            }
        }
        parent.remove(node);
        if (parent.getParent() == null) {
            logger.error(ZestZapUtils.getElement(parent));
            logger.error(ZestZapUtils.getElement(node));
        }
        if (parent.getParent().isRoot()) {
            if ((childZe instanceof ZestScript)) {
                logger.error(
                        "delete: unexpected child of root node: "
                                + childZe.getClass().getCanonicalName());
            }
        } else if (parentZe instanceof ZestScript) {
            if (childZe instanceof ZestStatement) {
                ((ZestScript) parentZe).remove((ZestStatement) childZe);
            } else {
                logger.error(
                        "delete: unexpected child of script node: "
                                + childZe.getClass().getCanonicalName());
            }
        } else if (parentZe instanceof ZestConditional) {
            ZestConditional zc = (ZestConditional) parentZe;
            if (childZe instanceof ZestExpression) {
                zc.setRootExpression(null);
            } else if (ZestZapUtils.getShadowLevel(parent) == 2) {
                zc.removeElse((ZestStatement) childZe);
            } else if (ZestZapUtils.getShadowLevel(parent) == 1) {
                zc.removeIf((ZestStatement) childZe);
            }
        } else if (parentZe instanceof ZestLoop<?>) {
            ZestLoop<?> zl = (ZestLoop<?>) parentZe;
            zl.getStatements().remove(childZe);
        } else if (parentZe instanceof ZestStructuredExpression) {
            ZestStructuredExpression zse = (ZestStructuredExpression) parentZe;
            zse.removeChildCondition((ZestExpressionElement) childZe);
        } else if (parentZe instanceof ZestRequest) {
            if (childZe instanceof ZestAssertion) {
                ((ZestRequest) parentZe).removeAssertion((ZestAssertion) childZe);
            } else {
                logger.error(
                        "delete: unexpected child of request node: "
                                + childZe.getClass().getCanonicalName());
            }
        } else if (parentZe instanceof ZestAction) {
            logger.error(
                    "delete: unexpected child of request node: "
                            + childZe.getClass().getCanonicalName());
        } else {
            logger.error("delete: unknown nodes: " + node.toString() + " " + parent.toString());
            logger.error("Parent user object: " + parentZe.getClass().getCanonicalName());
            logger.error("Child user object: " + childZe.getClass().getCanonicalName());
        }

        model.nodeStructureChanged(parent);
    }

    public ZestScriptWrapper getScriptWrapper(ScriptNode node) {
        if (node == null || node.getUserObject() == null) {
            return null;
        }
        if (node.getUserObject() instanceof ZestScriptWrapper) {
            return (ZestScriptWrapper) node.getUserObject();
        }
        return this.getScriptWrapper(node.getParent());
    }

    public ScriptNode getScriptWrapperNode(ScriptNode node) {
        if (node == null || node.getUserObject() == null) {
            return null;
        }
        if (node.getUserObject() instanceof ZestScriptWrapper) {
            return node;
        }
        return this.getScriptWrapperNode(node.getParent());
    }

    public void update(ScriptNode node) {
        logger.debug("Update node=" + node.getNodeName());
        ZestElement ze = ZestZapUtils.getElement(node);
        node.setNodeName(ZestZapUtils.toUiString(ze, true, ZestZapUtils.getShadowLevel(node)));
        model.nodeChanged(node);
        model.nodeStructureChanged(node.getParent());
    }

    public void nodeChanged(ScriptNode node) {
        model.nodeChanged(node);
    }

    /**
     * Switch the 2 specified nodes - they must have the same parent and be adjacent
     *
     * @param node1
     * @param node2
     */
    public void switchNodes(ScriptNode node1, ScriptNode node2) {
        if (!node1.getParent().equals(node2.getParent())) {
            logger.error(
                    "Nodes have different parents "
                            + node1.getNodeName()
                            + " "
                            + node2.getNodeName());
        } else {
            ScriptNode parent = node1.getParent();
            int i1 = parent.getIndex(node1);
            int i2 = parent.getIndex(node2);

            ScriptNode shadow1A = null;
            ScriptNode shadow1B = null;
            ScriptNode shadow2A = null;
            ScriptNode shadow2B = null;

            if (parent.getChildAfter(node1) != null
                    && ZestZapUtils.getShadowLevel((ScriptNode) parent.getChildAfter(node1)) > 0) {
                if (ZestZapUtils.getShadowLevel(
                                (ScriptNode) parent.getChildAfter(parent.getChildAfter(node1)))
                        == 2) {
                    shadow1B = (ScriptNode) parent.getChildAfter(parent.getChildAfter(node1));
                }
                if (ZestZapUtils.getShadowLevel((ScriptNode) parent.getChildAfter(node1)) == 1) {
                    shadow1A = (ScriptNode) parent.getChildAfter(node1);
                }
            }
            if (parent.getChildAfter(node2) != null
                    && ZestZapUtils.getShadowLevel((ScriptNode) parent.getChildAfter(node2)) > 0) {
                if (ZestZapUtils.getShadowLevel(
                                (ScriptNode) parent.getChildAfter(parent.getChildAfter(node2)))
                        == 2) {
                    shadow2B = (ScriptNode) parent.getChildAfter(parent.getChildAfter(node2));
                }
                if (ZestZapUtils.getShadowLevel((ScriptNode) parent.getChildAfter(node2)) == 1) {
                    shadow2A = (ScriptNode) parent.getChildAfter(node2);
                }
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
            if (shadow1A != null) {
                parent.remove(shadow1A);
                parent.insert(shadow1A, parent.getIndex(node1) + 1);
            }
            if (shadow1B != null) {
                parent.remove(shadow1B);
                parent.insert(shadow1B, parent.getIndex(node1) + 2);
            }
            if (shadow2A != null) {
                parent.remove(shadow2A);
                parent.insert(shadow2A, parent.getIndex(node2) + 1);
            }
            if (shadow2B != null) {
                parent.remove(shadow2B);
                parent.insert(shadow2B, parent.getIndex(node2) + 2);
            }
            model.nodeStructureChanged(parent);
        }
    }
}
