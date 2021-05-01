/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
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
package org.zaproxy.zap.extension.fuzz;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.apache.commons.configuration.FileConfiguration;
import org.parosproxy.paros.model.Model;
import org.zaproxy.zap.extension.httppanel.HttpPanel;
import org.zaproxy.zap.utils.ThreadUtils;
import org.zaproxy.zap.view.HttpPanelManager.HttpPanelComponentFactory;
import org.zaproxy.zap.view.HttpPanelManager.HttpPanelDefaultViewSelectorFactory;
import org.zaproxy.zap.view.HttpPanelManager.HttpPanelViewFactory;

/** The manager for message panels shown in the fuzzer dialogue. */
public final class MessagePanelManager {

    private final List<HttpPanel> panels;
    private final Map<String, HttpPanelComponentFactory> components;
    private final Map<String, Map<String, HttpPanelViewFactory>> views;
    private final Map<String, Map<String, HttpPanelDefaultViewSelectorFactory>> defaultViews;

    MessagePanelManager() {
        panels = new ArrayList<>();
        components = new HashMap<>();
        views = new HashMap<>();
        defaultViews = new HashMap<>();
    }

    /**
     * Adds the given message panel, to have the custom fuzz components and views.
     *
     * <p><strong>Note:</strong> Not part of the public API.
     *
     * @param panel the message panel.
     * @throws NullPointerException if panel is {@code null}.
     */
    public void addPanel(HttpPanel panel) {
        Objects.requireNonNull(panel);
        ThreadUtils.invokeAndWaitHandled(() -> addPanelImpl(panel));
    }

    private void addPanelImpl(HttpPanel panel) {
        panels.add(panel);

        FileConfiguration fileConfiguration = Model.getSingleton().getOptionsParam().getConfig();

        for (HttpPanelComponentFactory componentFactory : components.values()) {
            panel.addComponent(componentFactory.getNewComponent(), fileConfiguration);
        }

        for (Map.Entry<String, Map<String, HttpPanelViewFactory>> componentViews :
                views.entrySet()) {
            for (HttpPanelViewFactory viewFactory : componentViews.getValue().values()) {
                panel.addView(
                        componentViews.getKey(),
                        viewFactory.getNewView(),
                        viewFactory.getOptions(),
                        fileConfiguration);
            }
        }

        for (Map.Entry<String, Map<String, HttpPanelDefaultViewSelectorFactory>>
                componentDefaultViews : defaultViews.entrySet()) {
            for (HttpPanelDefaultViewSelectorFactory viewFactory :
                    componentDefaultViews.getValue().values()) {
                panel.addDefaultViewSelector(
                        componentDefaultViews.getKey(),
                        viewFactory.getNewDefaultViewSelector(),
                        viewFactory.getOptions());
            }
        }
    }

    /**
     * Removes the given message panel.
     *
     * <p><strong>Note:</strong> Not part of the public API.
     *
     * @param panel the message panel.
     * @throws NullPointerException if panel is {@code null}.
     */
    public void removePanel(HttpPanel panel) {
        Objects.requireNonNull(panel);
        ThreadUtils.invokeAndWaitHandled(() -> panels.remove(panel));
    }

    /**
     * Adds the given component factory.
     *
     * @param componentFactory the component factory.
     * @throws NullPointerException if the component factory is {@code null}.
     */
    public void addComponentFactory(HttpPanelComponentFactory componentFactory) {
        Objects.requireNonNull(componentFactory);
        ThreadUtils.invokeAndWaitHandled(() -> addComponentFactoryImpl(componentFactory));
    }

    private void addComponentFactoryImpl(HttpPanelComponentFactory componentFactory) {
        if (components.containsKey(componentFactory.getName())) {
            return;
        }
        components.put(componentFactory.getName(), componentFactory);

        FileConfiguration fileConfiguration = Model.getSingleton().getOptionsParam().getConfig();

        for (HttpPanel panel : panels) {
            panel.addComponent(componentFactory.getNewComponent(), fileConfiguration);

            final String componentName = componentFactory.getComponentName();

            Map<String, HttpPanelViewFactory> componentViews = views.get(componentName);
            if (componentViews != null) {
                for (HttpPanelViewFactory viewFactory : componentViews.values()) {
                    panel.addView(
                            componentName,
                            viewFactory.getNewView(),
                            viewFactory.getOptions(),
                            fileConfiguration);
                }
            }

            Map<String, HttpPanelDefaultViewSelectorFactory> defaultViewsComp =
                    defaultViews.get(componentName);
            if (defaultViewsComp != null) {
                for (HttpPanelDefaultViewSelectorFactory defaultViewSelector :
                        defaultViewsComp.values()) {
                    panel.addDefaultViewSelector(
                            componentName,
                            defaultViewSelector.getNewDefaultViewSelector(),
                            defaultViewSelector.getOptions());
                }
            }
        }
    }

    /**
     * Removes the component factory with the given name.
     *
     * @param componentFactoryName the name of the component factory.
     * @throws NullPointerException if the name of the component factory is {@code null}.
     */
    public void removeComponentFactory(String componentFactoryName) {
        Objects.requireNonNull(componentFactoryName);
        ThreadUtils.invokeAndWaitHandled(() -> components.remove(componentFactoryName));
    }

    /**
     * Removes the components with the given name.
     *
     * @param componentName the name of the component.
     * @throws NullPointerException if the given name is {@code null}.
     */
    public void removeComponents(String componentName) {
        Objects.requireNonNull(componentName);
        ThreadUtils.invokeAndWaitHandled(() -> removeComponentsImpl(componentName));
    }

    private void removeComponentsImpl(String componentName) {
        for (HttpPanel panel : panels) {
            panel.removeComponent(componentName);
        }
    }

    /**
     * Adds the given view factory for the components with the given name.
     *
     * @param componentName the name of the component.
     * @param viewFactory the view factory.
     * @throws NullPointerException if the given component name or view factory are {@code null}.
     */
    public void addViewFactory(String componentName, HttpPanelViewFactory viewFactory) {
        Objects.requireNonNull(componentName);
        Objects.requireNonNull(viewFactory);
        ThreadUtils.invokeAndWaitHandled(() -> addViewFactoryImpl(componentName, viewFactory));
    }

    private void addViewFactoryImpl(String componentName, HttpPanelViewFactory viewFactory) {
        Map<String, HttpPanelViewFactory> componentViews = views.get(componentName);
        if (componentViews == null) {
            componentViews = new HashMap<>();
            views.put(componentName, componentViews);
        } else if (views.containsKey(viewFactory.getName())) {
            return;
        }

        componentViews.put(viewFactory.getName(), viewFactory);

        FileConfiguration fileConfiguration = Model.getSingleton().getOptionsParam().getConfig();

        for (HttpPanel panel : panels) {
            panel.addView(
                    componentName,
                    viewFactory.getNewView(),
                    viewFactory.getOptions(),
                    fileConfiguration);
        }
    }

    /**
     * Removes the view factory with the given name for the components with the given name.
     *
     * @param componentName the name of the component.
     * @param viewFactoryName the name of the view factory.
     * @throws NullPointerException if the given names are {@code null}.
     */
    public void removeViewFactory(String componentName, String viewFactoryName) {
        Objects.requireNonNull(componentName);
        Objects.requireNonNull(viewFactoryName);
        ThreadUtils.invokeAndWaitHandled(
                () -> removeViewFactoryImpl(componentName, viewFactoryName));
    }

    private void removeViewFactoryImpl(String componentName, String viewFactoryName) {
        Map<String, HttpPanelViewFactory> componentViews = views.get(componentName);
        if (componentViews == null) {
            return;
        }

        HttpPanelViewFactory viewFactory = componentViews.get(viewFactoryName);
        if (viewFactory == null) {
            return;
        }

        componentViews.remove(viewFactoryName);

        if (componentViews.isEmpty()) {
            views.remove(componentName);
        }
    }

    /**
     * Removes the views with the given name from the component with the given name.
     *
     * @param componentName the name of the component.
     * @param viewName the name of the view.
     * @param options the options used to add the view.
     * @throws NullPointerException if the given names are {@code null}.
     */
    public void removeViews(String componentName, String viewName, Object options) {
        Objects.requireNonNull(componentName);
        Objects.requireNonNull(viewName);
        ThreadUtils.invokeAndWaitHandled(() -> removeViewsImpl(componentName, viewName, options));
    }

    private void removeViewsImpl(String componentName, String viewName, Object options) {
        for (HttpPanel panel : panels) {
            panel.removeView(componentName, viewName, options);
        }
    }

    /**
     * Adds a default view selector factory for the component with the given name.
     *
     * @param componentName the name of the component.
     * @param defaultViewSelectorFactory the default view selector factory.
     * @throws NullPointerException if the given name or factory are {@code null}.
     */
    public void addDefaultViewSelectorFactory(
            String componentName, HttpPanelDefaultViewSelectorFactory defaultViewSelectorFactory) {
        Objects.requireNonNull(componentName);
        Objects.requireNonNull(defaultViewSelectorFactory);
        ThreadUtils.invokeAndWaitHandled(
                () -> addDefaultViewSelectorFactoryImpl(componentName, defaultViewSelectorFactory));
    }

    private void addDefaultViewSelectorFactoryImpl(
            String componentName, HttpPanelDefaultViewSelectorFactory defaultViewSelectorFactory) {
        Map<String, HttpPanelDefaultViewSelectorFactory> componentDefaultViews =
                defaultViews.get(componentName);
        if (componentDefaultViews == null) {
            componentDefaultViews = new HashMap<>();
            defaultViews.put(componentName, componentDefaultViews);
        } else if (views.containsKey(defaultViewSelectorFactory.getName())) {
            return;
        }

        componentDefaultViews.put(defaultViewSelectorFactory.getName(), defaultViewSelectorFactory);

        for (HttpPanel panel : panels) {
            panel.addDefaultViewSelector(
                    componentName,
                    defaultViewSelectorFactory.getNewDefaultViewSelector(),
                    defaultViewSelectorFactory.getOptions());
        }
    }

    /**
     * Removes the default view selector factory for the component with the given name.
     *
     * @param componentName the name of the component.
     * @param defaultViewSelectorFactoryName the name of the default view selector factory.
     * @throws NullPointerException if the given names are {@code null}.
     */
    public void removeDefaultViewSelectorFactory(
            String componentName, String defaultViewSelectorFactoryName) {
        Objects.requireNonNull(componentName);
        Objects.requireNonNull(defaultViewSelectorFactoryName);
        ThreadUtils.invokeAndWaitHandled(
                () ->
                        removeDefaultViewSelectorFactoryImpl(
                                componentName, defaultViewSelectorFactoryName));
    }

    private void removeDefaultViewSelectorFactoryImpl(
            String componentName, String defaultViewSelectorFactoryName) {
        Map<String, HttpPanelDefaultViewSelectorFactory> componentDefaultViews =
                defaultViews.get(componentName);
        if (componentDefaultViews == null) {
            return;
        }

        HttpPanelDefaultViewSelectorFactory viewFactory =
                componentDefaultViews.get(defaultViewSelectorFactoryName);
        if (viewFactory == null) {
            return;
        }

        componentDefaultViews.remove(defaultViewSelectorFactoryName);

        if (componentDefaultViews.isEmpty()) {
            defaultViews.remove(componentName);
        }
    }

    /**
     * Removes the default view selectors for the component with the given name.
     *
     * @param componentName the name of the component.
     * @param defaultViewSelectorName the name of the default view selector factory.
     * @param options the options used to add the default view selector.
     */
    public void removeDefaultViewSelectors(
            String componentName, String defaultViewSelectorName, Object options) {
        Objects.requireNonNull(componentName);
        Objects.requireNonNull(defaultViewSelectorName);
        ThreadUtils.invokeAndWaitHandled(
                () ->
                        removeDefaultViewSelectorsImpl(
                                componentName, defaultViewSelectorName, options));
    }

    private void removeDefaultViewSelectorsImpl(
            String componentName, String defaultViewSelectorName, Object options) {
        for (HttpPanel panel : panels) {
            panel.removeDefaultViewSelector(componentName, defaultViewSelectorName, options);
        }
    }
}
