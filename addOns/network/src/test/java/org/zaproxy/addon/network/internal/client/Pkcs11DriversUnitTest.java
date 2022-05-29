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
package org.zaproxy.addon.network.internal.client;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.sameInstance;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import org.hamcrest.Matcher;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit test for {@link Pkcs11Drivers}. */
class Pkcs11DriversUnitTest extends TestUtils {

    @BeforeEach
    void setUp() throws Exception {
        setUpZap();
    }

    @Test
    void shouldUseBundledDriversIfNotFoundInHome() {
        // Given / When
        Pkcs11Drivers pkcs11Drivers = new Pkcs11Drivers();
        // Then
        assertBundledDrivers(pkcs11Drivers);
    }

    @Test
    void shouldUseDriversInHome() {
        // Given
        homeDriversWith(
                "<driver>\n"
                        + "  <name>Card A</name>\n"
                        + "  <path>/path/lib/a</path>\n"
                        + "  <slot>1</slot>\n"
                        + "  <slotListIndex>2</slotListIndex>\n"
                        + "</driver>\n"
                        + "<driver>\n"
                        + "  <name>Card B</name>\n"
                        + "  <path>/path/lib/b</path>\n"
                        + "  <slot>3</slot>\n"
                        + "  <slotListIndex>4</slotListIndex>\n"
                        + "</driver>");
        // When
        Pkcs11Drivers pkcs11Drivers = new Pkcs11Drivers();
        // When
        assertThat(pkcs11Drivers, hasSize(equalTo(2)));
        assertDriver(pkcs11Drivers.get(0), "Card A", "/path/lib/a", 1, 2);
        assertDriver(pkcs11Drivers.get(1), "Card B", "/path/lib/b", 3, 4);
    }

    @Test
    void shouldDefaultToBundledDriversIfDriversInHomeMalformed() {
        // Given
        homeDriversWith("<driver>");
        // When
        Pkcs11Drivers pkcs11Drivers = new Pkcs11Drivers();
        // When
        assertBundledDrivers(pkcs11Drivers);
    }

    @Test
    void shouldUseDriversInHomeEvenIfNonePresent() {
        // Given
        homeDriversWith("");
        // When
        Pkcs11Drivers pkcs11Drivers = new Pkcs11Drivers();
        // When
        assertThat(pkcs11Drivers, is(empty()));
    }

    @Test
    void shouldDefaultToEmptyNameIfNotPresent() {
        // Given
        homeDriversWith(
                "<driver>\n"
                        + "  <path>/path/lib/a</path>\n"
                        + "  <slot>1</slot>\n"
                        + "  <slotListIndex>2</slotListIndex>\n"
                        + "</driver>");
        // When
        Pkcs11Drivers pkcs11Drivers = new Pkcs11Drivers();
        // When
        assertThat(pkcs11Drivers, hasSize(equalTo(1)));
        assertDriver(pkcs11Drivers.get(0), "", "/path/lib/a", 1, 2);
    }

    @Test
    void shouldDefaultToEmptyLibraryIfNotPresent() {
        // Given
        homeDriversWith(
                "<driver>\n"
                        + "  <name>Card A</name>\n"
                        + "  <slot>1</slot>\n"
                        + "  <slotListIndex>2</slotListIndex>\n"
                        + "</driver>");
        // When
        Pkcs11Drivers pkcs11Drivers = new Pkcs11Drivers();
        // When
        assertThat(pkcs11Drivers, hasSize(equalTo(1)));
        assertDriver(pkcs11Drivers.get(0), "Card A", "", 1, 2);
    }

    @Test
    void shouldDefaultToZeroSlotIfNotPresent() {
        // Given
        homeDriversWith(
                "<driver>\n"
                        + "  <name>Card A</name>\n"
                        + "  <path>/path/lib/a</path>\n"
                        + "  <slotListIndex>2</slotListIndex>\n"
                        + "</driver>");
        // When
        Pkcs11Drivers pkcs11Drivers = new Pkcs11Drivers();
        // When
        assertThat(pkcs11Drivers, hasSize(equalTo(1)));
        assertDriver(pkcs11Drivers.get(0), "Card A", "/path/lib/a", 0, 2);
    }

    @Test
    void shouldDefaultToZeroSlotListIndexIfNotPresent() {
        // Given
        homeDriversWith(
                "<driver>\n"
                        + "  <name>Card A</name>\n"
                        + "  <path>/path/lib/a</path>\n"
                        + "  <slot>1</slot>\n"
                        + "</driver>");
        // When
        Pkcs11Drivers pkcs11Drivers = new Pkcs11Drivers();
        // When
        assertThat(pkcs11Drivers, hasSize(equalTo(1)));
        assertDriver(pkcs11Drivers.get(0), "Card A", "/path/lib/a", 1, 0);
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "not an int", "-1"})
    void shouldDefaultToZeroSlotIfInvalid(String slot) {
        // Given
        homeDriversWith(
                "<driver>\n"
                        + "  <name>Card A</name>\n"
                        + "  <path>/path/lib/a</path>\n"
                        + "  <slot>"
                        + slot
                        + "</slot>\n"
                        + "  <slotListIndex>2</slotListIndex>\n"
                        + "</driver>");
        // When
        Pkcs11Drivers pkcs11Drivers = new Pkcs11Drivers();
        // When
        assertThat(pkcs11Drivers, hasSize(equalTo(1)));
        assertDriver(pkcs11Drivers.get(0), "Card A", "/path/lib/a", 0, 2);
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "not an int", "-1"})
    void shouldDefaultToZeroSlotListIndexIfInvalid(String slotListIndex) {
        // Given
        homeDriversWith(
                "<driver>\n"
                        + "  <name>Card A</name>\n"
                        + "  <path>/path/lib/a</path>\n"
                        + "  <slot>1</slot>\n"
                        + "  <slotListIndex>"
                        + slotListIndex
                        + "</slotListIndex>\n"
                        + "</driver>");
        // When
        Pkcs11Drivers pkcs11Drivers = new Pkcs11Drivers();
        // When
        assertThat(pkcs11Drivers, hasSize(equalTo(1)));
        assertDriver(pkcs11Drivers.get(0), "Card A", "/path/lib/a", 1, 0);
    }

    @Test
    void shouldAddDriver() {
        // Given
        homeDriversWith("");
        Pkcs11Drivers pkcs11Drivers = new Pkcs11Drivers();
        // When
        pkcs11Drivers.add(new Pkcs11Driver("1", "", 0, 0));
        pkcs11Drivers.add(0, new Pkcs11Driver("2", "", 0, 0));
        // Then
        assertThat(pkcs11Drivers, hasSize(equalTo(2)));
        assertDriver(pkcs11Drivers.get(0), "2", "", 0, 0);
        assertDriver(pkcs11Drivers.get(1), "1", "", 0, 0);
    }

    @Test
    void shouldSetDriver() {
        // Given
        homeDriversWith("");
        Pkcs11Drivers pkcs11Drivers = new Pkcs11Drivers();
        pkcs11Drivers.add(new Pkcs11Driver("1", "", 0, 0));
        // When
        pkcs11Drivers.set(0, new Pkcs11Driver("1", "", 0, 0));
        pkcs11Drivers.set(0, new Pkcs11Driver("2", "", 0, 0));
        // Then
        assertThat(pkcs11Drivers, hasSize(equalTo(1)));
        assertDriver(pkcs11Drivers.get(0), "2", "", 0, 0);
    }

    @Test
    void shouldRemoveDriver() {
        // Given
        homeDriversWith("");
        Pkcs11Driver pkcs11Driver = new Pkcs11Driver("1", "", 0, 0);
        Pkcs11Drivers pkcs11Drivers = new Pkcs11Drivers();
        pkcs11Drivers.add(pkcs11Driver);
        // When
        Pkcs11Driver removedPkcs11Driver = pkcs11Drivers.remove(0);
        // Then
        assertThat(pkcs11Drivers, is(empty()));
        assertThat(removedPkcs11Driver, is(sameInstance(pkcs11Driver)));
    }

    @Test
    void shouldSaveToHomeDrivers() {
        // Given
        homeDriversWith("");
        Pkcs11Drivers pkcs11Drivers = new Pkcs11Drivers();
        pkcs11Drivers.add(new Pkcs11Driver("1", "/path/1", 1, 2));
        pkcs11Drivers.add(new Pkcs11Driver("2", "/path/2", 3, 4));
        // When
        pkcs11Drivers.save();
        // Then
        assertThat(pkcs11Drivers, hasSize(equalTo(2)));
        assertHomeDrivers(
                containsString(
                        "    <driver>\n"
                                + "        <name>1</name>\n"
                                + "        <path>/path/1</path>\n"
                                + "        <slot>1</slot>\n"
                                + "        <slotListIndex>2</slotListIndex>\n"
                                + "    </driver>\n"
                                + "    <driver>\n"
                                + "        <name>2</name>\n"
                                + "        <path>/path/2</path>\n"
                                + "        <slot>3</slot>\n"
                                + "        <slotListIndex>4</slotListIndex>\n"
                                + "    </driver>"));
    }

    @Test
    void shouldNotSaveToHomeDriversIfMalformed() {
        // Given
        homeDriversWith("<");
        Pkcs11Drivers pkcs11Drivers = new Pkcs11Drivers();
        pkcs11Drivers.add(new Pkcs11Driver("1", "/path/1", 1, 2));
        pkcs11Drivers.add(new Pkcs11Driver("2", "/path/2", 3, 4));
        // When
        pkcs11Drivers.save();
        // Then
        assertBundledDrivers(pkcs11Drivers);
        assertHomeDrivers(not(containsString("<driver>")));
    }

    @Test
    void shouldNotifyChangeListenersOnSave() {
        // Given
        homeDriversWith("");
        ChangeListener listener1 = mock(ChangeListener.class);
        ChangeListener listener2 = mock(ChangeListener.class);
        Pkcs11Drivers pkcs11Drivers = new Pkcs11Drivers();
        pkcs11Drivers.addChangeListener(listener1);
        pkcs11Drivers.addChangeListener(listener2);
        // When
        pkcs11Drivers.save();
        // Then
        verify(listener1).stateChanged(any(ChangeEvent.class));
        verify(listener2).stateChanged(any(ChangeEvent.class));
    }

    @Test
    void shouldRemoveChangeListener() {
        // Given
        homeDriversWith("");
        ChangeListener listener1 = mock(ChangeListener.class);
        ChangeListener listener2 = mock(ChangeListener.class);
        Pkcs11Drivers pkcs11Drivers = new Pkcs11Drivers();
        pkcs11Drivers.addChangeListener(listener1);
        pkcs11Drivers.addChangeListener(listener2);
        // When
        pkcs11Drivers.removeChangeListener(listener2);
        pkcs11Drivers.save();
        // Then
        verify(listener1).stateChanged(any(ChangeEvent.class));
        verifyNoInteractions(listener2);
    }

    private static void assertHomeDrivers(Matcher<String> matcher) {
        String content;
        try {
            content = new String(Files.readAllBytes(homeDriversPath()), StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        assertThat(content, matcher);
    }

    private static Path homeDriversPath() {
        return Paths.get(Constant.getZapHome(), "pkcs11-drivers.xml");
    }

    private static void assertBundledDrivers(Pkcs11Drivers pkcs11Drivers) {
        assertThat(pkcs11Drivers, hasSize(greaterThan(5)));
        assertThat(pkcs11Drivers.get(0).getName(), containsString("Windows"));
    }

    private static void assertDriver(
            Pkcs11Driver driver, String name, String library, int slot, int slotListIndex) {
        assertThat(driver.getName(), is(equalTo(name)));
        assertThat(driver.getLibrary(), is(equalTo(library)));
        assertThat(driver.getSlot(), is(equalTo(slot)));
        assertThat(driver.getSlotListIndex(), is(equalTo(slotListIndex)));
    }

    private static void homeDriversWith(String value) {
        String contents =
                "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n"
                        + "<driverConfiguration>\n"
                        + value
                        + "\n</driverConfiguration>";
        try {
            Files.write(homeDriversPath(), contents.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
