/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
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
package org.zaproxy.zap.extension.accessControl;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.httpclient.URIException;
import org.apache.log4j.Logger;
import org.parosproxy.paros.model.Model;
import org.zaproxy.zap.extension.accessControl.widgets.UriNode;
import org.zaproxy.zap.extension.accessControl.widgets.UriUtils;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.users.User;

public class ContextAccessRulesManager {
	private Context context;
	private Map<Integer, Map<UriNode, AccessRule>> rules;
	private static final Logger log = Logger.getLogger(ContextAccessRulesManager.class);

	public ContextAccessRulesManager(int contextId) {
		this.context = Model.getSingleton().getSession().getContext(contextId);
		this.rules = new HashMap<>();
	}

	/**
	 * Instantiates a new context access rules manager by performing a copy of the provided
	 * ContextAccessRulesManager.
	 *
	 * @param rulesManager the rules manager
	 */
	public ContextAccessRulesManager(Context context, ContextAccessRulesManager rulesManager) {
		this.context = context;
		this.rules = new HashMap<>(rulesManager.rules.size());
		Map<UriNode, AccessRule> userRules;
		for (Map.Entry<Integer, Map<UriNode, AccessRule>> entry : rulesManager.rules.entrySet()) {
			userRules = new HashMap<>(entry.getValue());
			this.rules.put(entry.getKey(), userRules);
		}
	}

	/**
	 * Get the mapping of rules for the user or initialize if needed.
	 *
	 * @param userId the user id
	 * @return the user rules
	 */
	private Map<UriNode, AccessRule> getUserRules(int userId) {
		Map<UriNode, AccessRule> userRules = rules.get(userId);
		if (userRules == null) {
			userRules = new HashMap<>();
			this.rules.put(userId, userRules);
		}
		return userRules;
	}

	/**
	 * Gets the access rule for a user and a node, if any.
	 *
	 * @param userId the user id
	 * @param node the node
	 * @return the rule
	 */
	public AccessRule getDefinedRule(int userId, UriNode node) {
		AccessRule rule = getUserRules(userId).get(node);
		return rule == null ? AccessRule.INHERIT : rule;
	}

	/**
	 * Adds an access rule for a user and a node.
	 *
	 * @param userId the user id
	 * @param node the node
	 * @param rule the rule
	 * @return the access rule
	 */
	public void addRule(int userId, UriNode node, AccessRule rule) {
		// If the rule is INHERIT (default), remove it from the rules mapping as there's no need to
		// store it there
		if (rule == AccessRule.INHERIT)
			getUserRules(userId).remove(node);
		else
			getUserRules(userId).put(node, rule);
	}

	public AccessRule inferRule(UriNode contextTreeRoot, int userId, UriNode node) {
		Map<UriNode, AccessRule> userRules = getUserRules(userId);
		List<String> path = null;
		try {
			path = context.getUrlParamParser().getTreePath(node.getUri());
		} catch (URIException e) {
			e.printStackTrace();

		}

		// Check the hostname
		String hostname;
		try {
			hostname = UriUtils.getHostName(node.getUri());
		} catch (URIException e) {
			e.printStackTrace();
			return AccessRule.UNKNOWN;
		}

		AccessRule rule, inferredRule = AccessRule.UNKNOWN;
		UriNode parent = contextTreeRoot.findChild(hostname);
		if (parent != null) {
			rule = userRules.get(parent);
			if (rule != null && rule != AccessRule.INHERIT)
				inferredRule = rule;
		}

		if (parent == null || path == null || path.isEmpty())
			return inferredRule;

		// Replace the last 'segment' of the path with the actual node name
		log.debug("Inferring rule for: " + node + ". Path: " + path);
		// if (path.size() > 0)
		path.set(path.size() - 1, node.getNodeName());

		String pathSegment;

		// Navigate the tree down trying to find the target node, making sure we store the defined
		// access rule at each step, if different from INHERIT. This allows us to have the right
		// behavior and infer the access rule. We start with UNKNOWN
		for (int i = 0; i < path.size(); i++) {
			pathSegment = path.get(i);
			if (pathSegment != null && !pathSegment.equals("")) {
				// Find the child node that matches the segment
				parent = parent.findChild(pathSegment);
				if (parent == null) {
					log.info("Unable to find path segment while infering rule: " + pathSegment);
					break;
				}
				// Save it's access rule, if anything relevant
				rule = userRules.get(parent);
				if (rule != null && rule != AccessRule.INHERIT)
					inferredRule = rule;
			}
		}
		log.debug("Inferred rule for " + node + ": " + inferredRule);
		return inferredRule;
	}

	/**
	 * Clear any existing rules and copies the access rules from another rules manager for the
	 * provided list of users.
	 *
	 * @param sourceManager the source manager
	 * @param users the users for which to copy rules
	 */
	public void copyRulesFrom(ContextAccessRulesManager sourceManager, List<User> users) {
		this.rules.clear();
		Map<UriNode, AccessRule> userRules;
		for (User user : users) {
			userRules = sourceManager.rules.get(user.getId());
			if (userRules != null)
				this.rules.put(user.getId(), userRules);
		}
	}
}
