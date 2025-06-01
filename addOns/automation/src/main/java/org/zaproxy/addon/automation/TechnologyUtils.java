/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.addon.automation;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;

public class TechnologyUtils {

    private TechnologyUtils() {}

    public static List<String> techSetToExcludeList(TechSet ts) {
        List<String> list = new ArrayList<>();
        getFilteredExludeTech(ts.getIncludeTech(), ts.getExcludeTech())
                .forEach(tech -> list.add(tech.getName()));
        return list;
    }

    /**
     * @param incTech
     * @param excTech
     * @return The ZAP desktop stores 2 lists of technologies, one to include and one to exclude.
     *     This is ok in a ZAP context file but is very difficult to read if translated directly
     *     into YML.
     */
    public static Set<Tech> getFilteredExludeTech(Set<Tech> incTech, Set<Tech> excTech) {
        if (excTech.size() == 0) {
            // Simple case, nothing explicitly excluded, all good
            return excTech;
        }
        // If any children included, strip parent out of excluded
        Set<Tech> set =
                excTech.stream()
                        .filter(tech -> !childInSet(incTech, tech))
                        .collect(Collectors.toSet());

        // If parent excluded can strip out all of the children
        return set.stream().filter(tech -> !parentInSet(set, tech)).collect(Collectors.toSet());
    }

    public static TechSet getTechSet(TechnologyData data) {
        TechSet ts = new TechSet();
        if (data.getInclude() == null || data.getInclude().isEmpty()) {
            Tech.getAll().forEach(ts::include);
        } else {
            data.getInclude().stream()
                    .map(name -> getTech(name, null))
                    .filter(Objects::nonNull)
                    .forEach(
                            tech -> {
                                ts.include(tech);
                                Tech.getAll().stream().filter(t -> t.is(tech)).forEach(ts::include);
                            });
        }
        if (data.getExclude() != null) {
            data.getExclude().stream()
                    .forEach(
                            name -> TechnologyUtils.removeTechAndChildren(ts, getTech(name, null)));
        }
        return ts;
    }

    public static boolean parentInSet(Set<Tech> set, Tech tech) {
        if (tech == null || tech.getParent() == null) {
            return false;
        }
        if (set.contains(tech.getParent())) {
            return true;
        }
        return parentInSet(set, tech.getParent());
    }

    public static boolean childInSet(Set<Tech> set, Tech tech) {
        return set.stream().anyMatch(child -> childHasParent(child, tech));
    }

    public static boolean childHasParent(Tech child, Tech parent) {
        if (child == null || child.getParent() == null || parent == null) {
            return false;
        }
        if (parent.equals(child.getParent())) {
            return true;
        }
        return childHasParent(child.getParent(), parent);
    }

    public static void removeTechAndParents(Set<Tech> set, Tech tech) {
        if (tech == null) {
            return;
        }
        set.remove(tech);
        if (tech.getParent() != null) {
            removeTechAndParents(set, tech.getParent());
        }
    }

    public static void removeTechAndParents(TechSet tset, Tech tech) {
        if (tech == null) {
            return;
        }
        tset.exclude(tech);
        if (tech.getParent() != null) {
            removeTechAndParents(tset, tech.getParent());
        }
    }

    public static void removeTechAndChildren(TechSet tset, Tech tech) {
        if (tech == null) {
            return;
        }
        tset.exclude(tech);
        Set<Tech> toRemove =
                tset.getIncludeTech().stream()
                        .filter(child -> childHasParent(child, tech))
                        .collect(Collectors.toSet());
        toRemove.stream().forEach(t -> tset.exclude(t));
    }

    public static Tech getTech(Set<Tech> set, String name, AutomationProgress progress) {
        Optional<Tech> res =
                set.stream()
                        .filter(
                                tech ->
                                        tech.getName().equalsIgnoreCase(name)
                                                || tech.toString().equalsIgnoreCase(name))
                        .findAny();
        if (res.isEmpty()) {
            if (progress != null) {
                progress.warn(
                        Constant.messages.getString("automation.error.context.unknowntech", name));
            }
            return null;
        }
        return res.get();
    }

    /**
     * Get the Tech for the given name. Note that Tech.get(string) requires the full hierarchy to be
     * specified.
     *
     * @param name
     * @return The Tech for the given name, ignoring the hierarchy
     */
    public static Tech getTech(String name, AutomationProgress progress) {
        return getTech(Tech.getAll(), name, progress);
    }
}
