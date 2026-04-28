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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.is;

import java.io.IOException;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zaproxy.addon.wstgmapper.model.WstgTestStatus;

/**
 * Unit tests for {@link WstgMapperChecklistManager}.
 *
 * <p>They cover the mutable state container used by the UI and alert consumer, including trigger
 * tracking, manual edits, and listener notifications.
 */
class WstgMapperChecklistManagerTest {

    private WstgMapperChecklistManager manager;

    @BeforeEach
    void setUp() throws IOException {
        manager = new WstgMapperChecklistManager(null);
    }

    @Test
    void triggerTestsAddsIdsAndMarksThemTriggered() {
        manager.triggerTests(Set.of("WSTG-INFO-01", "WSTG-SESS-02"));

        assertThat(manager.getTriggeredIds(), containsInAnyOrder("WSTG-INFO-01", "WSTG-SESS-02"));
        assertThat(manager.isTriggered("WSTG-INFO-01"), is(true));
    }

    @Test
    void triggerTestsOnlyNotifiesWhenNewIdsAreAdded() {
        AtomicInteger changeCount = new AtomicInteger();
        manager.addListener(changeCount::incrementAndGet);

        manager.triggerTests(Set.of("WSTG-INFO-01"));
        manager.triggerTests(Set.of("WSTG-INFO-01"));

        assertThat(changeCount.get(), is(1));
    }

    @Test
    void clearTriggeredResetsTriggeredSet() {
        manager.triggerTests(Set.of("WSTG-INFO-01"));

        manager.clearTriggered();

        assertThat(manager.getTriggeredIds(), is(empty()));
    }

    @Test
    void testStatusIsStoredWhenNoParamIsProvided() {
        manager.setTestStatus("WSTG-INFO-01", WstgTestStatus.PASSED);

        assertThat(manager.getTestStatus("WSTG-INFO-01"), is(WstgTestStatus.PASSED));
    }

    @Test
    void testNotesAreStoredWhenNoParamIsProvided() {
        manager.setTestNotes("WSTG-INFO-01", "Needs manual validation.");

        assertThat(manager.getTestNotes("WSTG-INFO-01"), is("Needs manual validation."));
    }

    @Test
    void detectedTechnologiesAreStoredCaseInsensitively() {
        manager.addDetectedTechnology("MySQL");
        manager.addDetectedTechnology("mysql");

        assertThat(manager.getDetectedTechnologies(), containsInAnyOrder("mysql"));
    }

    @Test
    void removedListenerIsNotCalled() {
        AtomicInteger changeCount = new AtomicInteger();
        WstgMapperChecklistManager.WstgMapperListener listener = changeCount::incrementAndGet;
        manager.addListener(listener);
        manager.removeListener(listener);

        manager.notifyChanged();

        assertThat(changeCount.get(), is(0));
    }
}
