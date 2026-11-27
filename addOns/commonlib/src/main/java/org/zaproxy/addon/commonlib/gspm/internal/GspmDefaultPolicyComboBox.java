/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.addon.commonlib.gspm.internal;

import java.awt.EventQueue;
import java.util.List;
import java.util.Objects;
import java.util.function.Consumer;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JComboBox;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.commonlib.gspm.GspmPolicy;
import org.zaproxy.addon.commonlib.gspm.GspmRegistry;
import org.zaproxy.addon.commonlib.gspm.GspmRule;
import org.zaproxy.zap.utils.Stats;

/**
 * The combo box of the main tool bar to choose the {@link GspmDefaultPolicy default policy}.
 *
 * <p>Lists the policies, sorted ignoring case, and follows the changes to the policies and to the
 * default policy.
 */
public class GspmDefaultPolicyComboBox extends JComboBox<String> {

    private static final long serialVersionUID = 1L;

    private final transient GspmRegistry registry;
    private final transient Consumer<String> policySelector;
    private final transient GspmRegistry.RegistryListener listener;

    private boolean updating;

    /**
     * Constructs a {@code GspmDefaultPolicyComboBox}.
     *
     * @param registry the registry, to get the policies and the default one.
     * @param policySelector called with the name of the policy chosen by the user.
     */
    public GspmDefaultPolicyComboBox(GspmRegistry registry, Consumer<String> policySelector) {
        this.registry = Objects.requireNonNull(registry);
        this.policySelector = Objects.requireNonNull(policySelector);

        String tooltip = Constant.messages.getString("commonlib.gspm.defaultpolicy.tooltip");
        setToolTipText(tooltip);
        getAccessibleContext().setAccessibleName(tooltip);
        addActionListener(e -> policyChosen());

        listener =
                new GspmRegistry.RegistryListener() {
                    @Override
                    public void ruleRegistered(GspmRule rule) {
                        // Nothing to do.
                    }

                    @Override
                    public void ruleUnregistered(GspmRule rule) {
                        // Nothing to do.
                    }

                    @Override
                    public void policyAdded(GspmPolicy policy) {
                        refreshLater();
                    }

                    @Override
                    public void policyRemoved(String policyName) {
                        refreshLater();
                    }

                    @Override
                    public void policyRenamed(String oldName, String newName) {
                        refreshLater();
                    }

                    @Override
                    public void currentPolicyChanged(String policyName) {
                        refreshLater();
                    }
                };
        registry.addListener(listener);
        refresh();
    }

    /** Stops following the changes, to be called when no longer used. */
    public void unload() {
        registry.removeListener(listener);
    }

    private void refreshLater() {
        if (EventQueue.isDispatchThread()) {
            refresh();
        } else {
            EventQueue.invokeLater(this::refresh);
        }
    }

    /** Updates the policies listed and the one selected. */
    void refresh() {
        updating = true;
        try {
            List<String> names =
                    registry.getAllPolicies().stream()
                            .map(GspmPolicy::getName)
                            .sorted(String.CASE_INSENSITIVE_ORDER)
                            .toList();
            setModel(new DefaultComboBoxModel<>(names.toArray(new String[0])));
            String current = registry.getCurrentPolicy();
            if (current != null && names.contains(current)) {
                setSelectedItem(current);
            } else {
                setSelectedIndex(-1);
            }
            // Otherwise it's stretched in the tool bar.
            setMaximumSize(null);
            setMaximumSize(getPreferredSize());
        } finally {
            updating = false;
        }
        revalidate();
    }

    private void policyChosen() {
        if (updating) {
            return;
        }
        String name = (String) getSelectedItem();
        if (name == null || name.equals(registry.getCurrentPolicy())) {
            return;
        }
        if (registry.getPolicy(name) == null) {
            refresh();
            return;
        }
        policySelector.accept(name);
        Stats.incCounter("stats.ui.maintoolbar.dropdown.gspm.defaultpolicy");
    }
}
