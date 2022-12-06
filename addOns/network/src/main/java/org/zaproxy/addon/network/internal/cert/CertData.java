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
package org.zaproxy.addon.network.internal.cert;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class CertData {

    private String commonName;
    private List<Name> subjectAlternativeNames;

    public CertData() {
        subjectAlternativeNames = new ArrayList<>();
    }

    public CertData(String commonName) {
        this();
        this.commonName = commonName;
        if (commonName != null) {
            addSubjectAlternativeName(new Name(Name.DNS, commonName));
        }
    }

    public String getCommonName() {
        return commonName;
    }

    public void addSubjectAlternativeName(Name subjectAlternativeName) {
        subjectAlternativeNames.add(subjectAlternativeName);
    }

    public boolean isSubjectAlternativeNameIsCritical() {
        return commonName == null;
    }

    public Name[] getSubjectAlternativeNames() {
        Name[] subjectAlternativeNamesArray = new Name[subjectAlternativeNames.size()];
        return subjectAlternativeNames.toArray(subjectAlternativeNamesArray);
    }

    @Override
    public int hashCode() {
        return Objects.hash(commonName, subjectAlternativeNames);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (!(obj instanceof CertData)) {
            return false;
        }
        CertData certData = (CertData) obj;
        return Objects.equals(commonName, certData.commonName)
                && Objects.equals(subjectAlternativeNames, certData.subjectAlternativeNames);
    }

    public static class Name {
        public static final int DNS = 2;
        public static final int IP_ADDRESS = 7;

        private int type;
        private String value;

        public Name(int type, String value) {
            this.type = type;
            this.value = value;
        }

        public int getType() {
            return type;
        }

        public String getValue() {
            return value;
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj == null) {
                return false;
            }
            if (!(obj instanceof Name)) {
                return false;
            }

            Name name = (Name) obj;

            if (getType() != name.getType()) {
                return false;
            }
            return Objects.equals(getValue(), name.getValue());
        }

        @Override
        public int hashCode() {
            return Objects.hash(getType(), getValue());
        }
    }
}
