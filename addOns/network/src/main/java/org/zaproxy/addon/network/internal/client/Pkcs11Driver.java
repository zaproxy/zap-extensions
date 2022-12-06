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

import java.util.Objects;
import org.zaproxy.addon.network.internal.client.Pkcs11Configuration.Pkcs11ConfigurationBuilder;

/**
 * A PKCS#11 driver.
 *
 * <p>Contains the name, library path, slot, and slot list index.
 */
public class Pkcs11Driver {

    private final String name;
    private final String library;
    private final int slot;
    private final int slotListIndex;

    /**
     * Constructs a {@code Pkcs11Driver} with the given data.
     *
     * @param name the name, must not be {@code null}.
     * @param library the library path.
     * @param slot the slot.
     * @param slotListIndex the slot list index.
     * @throws NullPointerException if the {@code name} or {@code library} is {@code null}.
     * @throws IllegalArgumentException if the {@code slot} or the {@code slotListIndex} is
     *     negative.
     */
    public Pkcs11Driver(String name, String library, int slot, int slotListIndex) {
        this.name = Objects.requireNonNull(name);
        this.library = Objects.requireNonNull(library);
        this.slot = validatePositive("slot", slot);
        this.slotListIndex = validatePositive("slotListIndex", slotListIndex);
    }

    private static int validatePositive(String parameter, int value) {
        if (value < 0) {
            throw new IllegalArgumentException("The " + parameter + " must not be negative.");
        }
        return value;
    }

    /**
     * Gets the name.
     *
     * @return the name, never {@code null}.
     */
    public String getName() {
        return name;
    }

    /**
     * Gets the library.
     *
     * @return the library, never {@code null}.
     */
    public String getLibrary() {
        return library;
    }

    /**
     * Gets the slot.
     *
     * @return the slot.
     */
    public int getSlot() {
        return slot;
    }

    /**
     * Gets the slot list index.
     *
     * @return the slot list index.
     */
    public int getSlotListIndex() {
        return slotListIndex;
    }

    /**
     * Gets the configuration to use with a PKCS#11 provider.
     *
     * @param useSlotListIndex {@code true} to use the slot list index, {@code false} to use the
     *     slot.
     * @return the configuration.
     */
    public String getConfiguration(boolean useSlotListIndex) {
        Pkcs11ConfigurationBuilder confBuilder =
                Pkcs11Configuration.builder().setName(getName()).setLibrary(getLibrary());
        if (useSlotListIndex) {
            confBuilder.setSlotListIndex(getSlotListIndex());
        } else {
            confBuilder.setSlotId(getSlot());
        }
        return confBuilder.build().toString();
    }

    @Override
    public int hashCode() {
        return Objects.hash(library, name, slot, slotListIndex);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof Pkcs11Driver)) {
            return false;
        }
        Pkcs11Driver other = (Pkcs11Driver) obj;
        return Objects.equals(library, other.library)
                && Objects.equals(name, other.name)
                && slot == other.slot
                && slotListIndex == other.slotListIndex;
    }

    @Override
    public String toString() {
        return getName();
    }
}
