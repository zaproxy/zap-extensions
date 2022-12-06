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
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** Unit test for {@link Pkcs11Driver}. */
class Pkcs11DriverUnitTest {

    private static final String NAME = "Card 1";
    private static final String LIBRARY = "/path/to/library";
    private static final int SLOT = 0;
    private static final int SLOT_LIST_INDEX = 1;

    @Test
    void shouldNotCreatePkcs11DriverWithNullName() {
        // Given
        String name = null;
        // When / Then
        assertThrows(
                NullPointerException.class,
                () -> new Pkcs11Driver(name, LIBRARY, SLOT, SLOT_LIST_INDEX));
    }

    @Test
    void shouldNotCreatePkcs11DriverWithNullLibrary() {
        // Given
        String library = null;
        // When / Then
        assertThrows(
                NullPointerException.class,
                () -> new Pkcs11Driver(NAME, library, SLOT, SLOT_LIST_INDEX));
    }

    @ParameterizedTest
    @ValueSource(ints = {-10, -1})
    void shouldNotCreatePkcs11DriverWithInvalidSlot(int slot) {
        assertThrows(
                IllegalArgumentException.class,
                () -> new Pkcs11Driver(NAME, LIBRARY, slot, SLOT_LIST_INDEX));
    }

    @ParameterizedTest
    @ValueSource(ints = {-10, -1})
    void shouldNotCreatePkcs11DriverWithInvalidSlotListIndex(int slotListIndex) {
        assertThrows(
                IllegalArgumentException.class,
                () -> new Pkcs11Driver(NAME, LIBRARY, SLOT, slotListIndex));
    }

    @Test
    void shouldCreatePkcs11Driver() {
        // Given
        String name = "Card 2";
        String library = "Library";
        int slot = 2;
        int slotListIndex = 3;
        // When
        Pkcs11Driver pkcs11Driver = new Pkcs11Driver(name, library, slot, slotListIndex);
        // Then
        assertThat(pkcs11Driver.getName(), is(equalTo(name)));
        assertThat(pkcs11Driver.getLibrary(), is(equalTo(library)));
        assertThat(pkcs11Driver.getSlot(), is(equalTo(slot)));
        assertThat(pkcs11Driver.getSlotListIndex(), is(equalTo(slotListIndex)));
    }

    @Test
    void shouldProduceConsistentHashCode() {
        // Given
        Pkcs11Driver pkcs11Driver = new Pkcs11Driver("Card 3", "Library 2", 1, 2);
        // When
        int hashCode = pkcs11Driver.hashCode();
        // Then
        assertThat(hashCode, is(equalTo(-1549807336)));
    }

    @Test
    void shouldBeEqualToItself() {
        // Given
        Pkcs11Driver pkcs11Driver = new Pkcs11Driver(NAME, LIBRARY, SLOT, SLOT_LIST_INDEX);
        // When
        boolean equals = pkcs11Driver.equals(pkcs11Driver);
        // Then
        assertThat(equals, is(equalTo(true)));
    }

    @Test
    void shouldBeEqualToDifferentPkcs11DriverWithSameContents() {
        // Given
        Pkcs11Driver pkcs11Driver = new Pkcs11Driver(NAME, LIBRARY, SLOT, SLOT_LIST_INDEX);
        Pkcs11Driver otherEqualPkcs11Driver =
                new Pkcs11Driver(NAME, LIBRARY, SLOT, SLOT_LIST_INDEX);
        // When
        boolean equals = pkcs11Driver.equals(otherEqualPkcs11Driver);
        // Then
        assertThat(equals, is(equalTo(true)));
    }

    @Test
    void shouldNotBeEqualToNull() {
        // Given
        Pkcs11Driver pkcs11Driver = new Pkcs11Driver(NAME, LIBRARY, SLOT, SLOT_LIST_INDEX);
        // When
        boolean equals = pkcs11Driver.equals(null);
        // Then
        assertThat(equals, is(equalTo(false)));
    }

    @Test
    void shouldNotBeEqualToPkcs11DriverWithJustDifferentName() {
        // Given
        Pkcs11Driver pkcs11Driver = new Pkcs11Driver(NAME, LIBRARY, SLOT, SLOT_LIST_INDEX);
        Pkcs11Driver otherPkcs11Driver =
                new Pkcs11Driver("Other name", LIBRARY, SLOT, SLOT_LIST_INDEX);
        // When
        boolean equals = pkcs11Driver.equals(otherPkcs11Driver);
        // Then
        assertThat(equals, is(equalTo(false)));
    }

    @Test
    void shouldNotBeEqualToPkcs11DriverWithJustDifferentLibrary() {
        // Given
        Pkcs11Driver pkcs11Driver = new Pkcs11Driver(NAME, LIBRARY, SLOT, SLOT_LIST_INDEX);
        Pkcs11Driver otherPkcs11Driver =
                new Pkcs11Driver(NAME, "Other Library", SLOT, SLOT_LIST_INDEX);
        // When
        boolean equals = pkcs11Driver.equals(otherPkcs11Driver);
        // Then
        assertThat(equals, is(equalTo(false)));
    }

    @Test
    void shouldNotBeEqualToPkcs11DriverWithJustDifferentSlot() {
        // Given
        Pkcs11Driver pkcs11Driver = new Pkcs11Driver(NAME, LIBRARY, SLOT, SLOT_LIST_INDEX);
        Pkcs11Driver otherPkcs11Driver = new Pkcs11Driver(NAME, LIBRARY, SLOT + 2, SLOT_LIST_INDEX);
        // When
        boolean equals = pkcs11Driver.equals(otherPkcs11Driver);
        // Then
        assertThat(equals, is(equalTo(false)));
    }

    @Test
    void shouldNotBeEqualToPkcs11DriverWithJustDifferentSlotListIndex() {
        // Given
        Pkcs11Driver pkcs11Driver = new Pkcs11Driver(NAME, LIBRARY, SLOT, SLOT_LIST_INDEX);
        Pkcs11Driver otherPkcs11Driver = new Pkcs11Driver(NAME, LIBRARY, SLOT, SLOT_LIST_INDEX + 3);
        // When
        boolean equals = pkcs11Driver.equals(otherPkcs11Driver);
        // Then
        assertThat(equals, is(equalTo(false)));
    }

    @Test
    void shouldBeEqualToExtendedPkcs11Driver() {
        // Given
        Pkcs11Driver pkcs11Driver = new Pkcs11Driver(NAME, LIBRARY, SLOT, SLOT_LIST_INDEX);
        Pkcs11Driver otherPkcs11Driver = new Pkcs11Driver(NAME, LIBRARY, SLOT, SLOT_LIST_INDEX) {
                    // Anonymous Pkcs11Driver
                };
        // When
        boolean equals = pkcs11Driver.equals(otherPkcs11Driver);
        // Then
        assertThat(equals, is(equalTo(true)));
    }

    @Test
    void shouldNotBeEqualToDifferentType() {
        // Given
        Pkcs11Driver pkcs11Driver = new Pkcs11Driver(NAME, LIBRARY, SLOT, SLOT_LIST_INDEX);
        String otherType = "";
        // When
        boolean equals = pkcs11Driver.equals(otherType);
        // Then
        assertThat(equals, is(equalTo(false)));
    }

    @Test
    void shouldReturnNameAsStringRepresentation() {
        // Given
        String name = "Cards A";
        Pkcs11Driver pkcs11Driver = new Pkcs11Driver(name, LIBRARY, SLOT, SLOT_LIST_INDEX);
        // When
        String representation = pkcs11Driver.toString();
        // Then
        assertThat(representation, is(equalTo(name)));
    }

    @Test
    void shouldGetConfigurationWithSlotListIndex() {
        // Given
        boolean useSlotListIndex = true;
        Pkcs11Driver pkcs11Driver = new Pkcs11Driver(NAME, LIBRARY, SLOT, SLOT_LIST_INDEX);
        // When
        String configuration = pkcs11Driver.getConfiguration(useSlotListIndex);
        // Then
        assertThat(configuration, containsString("slotListIndex = " + SLOT_LIST_INDEX));
        assertThat(configuration, not(containsString("slot = ")));
    }

    @Test
    void shouldGetConfigurationWithSlot() {
        // Given
        boolean useSlotListIndex = false;
        Pkcs11Driver pkcs11Driver = new Pkcs11Driver(NAME, LIBRARY, SLOT, SLOT_LIST_INDEX);
        // When
        String configuration = pkcs11Driver.getConfiguration(useSlotListIndex);
        // Then
        assertThat(configuration, containsString("slot = " + SLOT));
        assertThat(configuration, not(containsString("slotListIndex = ")));
    }

    @Test
    void shouldGetConfigurationWithNameQuoted() {
        // Given
        Pkcs11Driver pkcs11Driver = new Pkcs11Driver(NAME, LIBRARY, SLOT, SLOT_LIST_INDEX);
        // When
        String configuration = pkcs11Driver.getConfiguration(false);
        // Then
        assertThat(configuration, containsString("name = \"" + NAME + "\""));
    }

    @Test
    void shouldGetConfigurationWithLibrary() {
        // Given
        Pkcs11Driver pkcs11Driver = new Pkcs11Driver(NAME, LIBRARY, SLOT, SLOT_LIST_INDEX);
        // When
        String configuration = pkcs11Driver.getConfiguration(false);
        // Then
        assertThat(configuration, containsString("library = " + LIBRARY));
    }
}
