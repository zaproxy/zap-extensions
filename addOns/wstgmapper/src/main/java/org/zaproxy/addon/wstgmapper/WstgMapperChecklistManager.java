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
package org.zaproxy.addon.wstgmapper;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import org.zaproxy.addon.wstgmapper.model.WstgTestStatus;

/**
 * Central state holder for the checklist shown by the add-on.
 *
 * <p>It tracks manual statuses, tester notes, triggered tests, and detected technologies, while
 * delegating persisted values to {@link WstgMapperParam} when a session-backed config is available.
 */
public class WstgMapperChecklistManager {

    @FunctionalInterface
    public interface WstgMapperListener {
        void changed();
    }

    private final WstgMapperParam param;

    private final Map<String, WstgTestStatus> localStatuses = new ConcurrentHashMap<>();
    private final Map<String, String> localNotes = new ConcurrentHashMap<>();
    private final Set<String> triggeredIds = Collections.synchronizedSet(new LinkedHashSet<>());
    private final Set<String> detectedTechnologies = Collections.synchronizedSet(new TreeSet<>());
    private final CopyOnWriteArrayList<WstgMapperListener> listeners = new CopyOnWriteArrayList<>();

    public WstgMapperChecklistManager(WstgMapperParam param) {
        this.param = param;
    }

    public void triggerTests(Set<String> wstgIds) {
        if (wstgIds == null || wstgIds.isEmpty()) {
            return;
        }

        boolean changed = false;
        for (String id : wstgIds) {
            if (id != null && !id.isBlank() && triggeredIds.add(id)) {
                changed = true;
            }
        }
        if (changed) {
            notifyChanged();
        }
    }

    public void setTestStatus(String id, WstgTestStatus status) {
        WstgTestStatus normalized = status != null ? status : WstgTestStatus.NOT_TESTED;
        if (normalized == getTestStatus(id)) {
            return;
        }

        if (param != null) {
            param.setStatus(id, normalized);
        } else if (normalized == WstgTestStatus.NOT_TESTED) {
            localStatuses.remove(id);
        } else {
            localStatuses.put(id, normalized);
        }
        notifyChanged();
    }

    public WstgTestStatus getTestStatus(String id) {
        if (param != null) {
            return param.getStatus(id);
        }
        return localStatuses.getOrDefault(id, WstgTestStatus.NOT_TESTED);
    }

    public void setTestNotes(String id, String notes) {
        String normalized = notes != null ? notes : "";
        if (normalized.equals(getTestNotes(id))) {
            return;
        }

        if (param != null) {
            param.setNotes(id, normalized);
        } else if (normalized.isEmpty()) {
            localNotes.remove(id);
        } else {
            localNotes.put(id, normalized);
        }
        notifyChanged();
    }

    public String getTestNotes(String id) {
        if (param != null) {
            return param.getNotes(id);
        }
        return localNotes.getOrDefault(id, "");
    }

    public boolean isTriggered(String id) {
        return triggeredIds.contains(id);
    }

    public Set<String> getTriggeredIds() {
        synchronized (triggeredIds) {
            return Collections.unmodifiableSet(new LinkedHashSet<>(triggeredIds));
        }
    }

    public Set<String> getDetectedTechnologies() {
        synchronized (detectedTechnologies) {
            return Collections.unmodifiableSet(new TreeSet<>(detectedTechnologies));
        }
    }

    public void addDetectedTechnology(String technology) {
        if (technology == null || technology.isBlank()) {
            return;
        }
        if (detectedTechnologies.add(technology.trim().toLowerCase())) {
            notifyChanged();
        }
    }

    public void clearTriggered() {
        triggeredIds.clear();
        notifyChanged();
    }

    public void clearDetectedTechnologies() {
        detectedTechnologies.clear();
        notifyChanged();
    }

    public void addListener(WstgMapperListener listener) {
        if (listener != null) {
            listeners.addIfAbsent(listener);
        }
    }

    public void removeListener(WstgMapperListener listener) {
        listeners.remove(listener);
    }

    public void notifyChanged() {
        for (WstgMapperListener listener : listeners) {
            listener.changed();
        }
    }
}
