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
package org.zaproxy.addon.commonlib.binlist;

/**
 * A Bank Identification Number (BIN) record.
 *
 * <p>Contains information about the bank/issuer of a credit card.
 *
 * @since 1.0.0
 */
public final class BinRecord {
    private final String bin;
    private final String brand;
    private final String category;
    private final String issuer;

    BinRecord(String bin, String brand, String category, String issuer) {
        this.bin = bin;
        this.brand = brand;
        this.category = category;
        this.issuer = issuer;
    }

    public String getBin() {
        return bin;
    }

    public String getBrand() {
        return brand;
    }

    public String getCategory() {
        return category;
    }

    public String getIssuer() {
        return issuer;
    }

    @Override
    public String toString() {
        StringBuilder recString = new StringBuilder(75);
        recString.append("BIN: ").append(bin).append('\n');
        recString.append("Brand: ").append(brand).append('\n');
        recString.append("Category: ").append(category).append('\n');
        recString.append("Issuer: ").append(issuer);
        return recString.toString();
    }
}
