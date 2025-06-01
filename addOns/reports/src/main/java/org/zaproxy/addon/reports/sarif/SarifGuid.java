/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.addon.reports.sarif;

import java.util.Objects;
import java.util.UUID;

/**
 * Represents a GUID for Sarif
 * https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317438
 */
public class SarifGuid {

    private String guid;

    private SarifGuid() {
        // force to use factory methods
    }

    public static SarifGuid createCweGuid(int cweId) {
        return createByProvider("" + cweId, SarifToolData.INSTANCE.getCwe());
    }

    public static SarifGuid createForTaxa(String identifier, SarifTaxonomy taxonomy) {
        return createByProvider(identifier, taxonomy);
    }

    public static SarifGuid createToolComponentGUID(SarifTaxonomyDataProvider component) {
        return createByProvider("<<tool-component>>", component);
    }

    private static SarifGuid createByIdentifier(String identifier) {
        SarifGuid sarifGuid = new SarifGuid();

        UUID nameBasedUUID = UUID.nameUUIDFromBytes(identifier.getBytes());
        sarifGuid.guid = nameBasedUUID.toString();

        return sarifGuid;
    }

    /**
     * Creates a SARIF guid object by using data from taxonomy provider and the given taxonomy id.
     * If your are calling this method twice for the same given id and same provider the created
     * objects will be equal. Otherwise the created objects are NOT equal.
     *
     * @param id represents the identifier inside the taxonomy
     * @param provider provides taxonomy details
     * @return created guid object
     */
    private static SarifGuid createByProvider(String id, SarifTaxonomyDataProvider provider) {
        // e.g. when we use 79 as (CWE) id and the provider is our CWE 4.4 provider we
        // will have
        // internal identifier "name:CWE:4.4:79" - if we change to CWE 4.5 (in future),
        // the same CWE 79
        // would have a different guid because the taxonomy version differs and we will
        // have the internal identifier "name:CWE:4.5:79"
        String identifier =
                "name:" + provider.getName() + ":" + provider.getTaxonomyVersion() + ":" + id;
        return createByIdentifier(identifier);
    }

    public String getGuid() {
        return guid;
    }

    @Override
    public String toString() {
        return getGuid();
    }

    @Override
    public int hashCode() {
        return Objects.hash(guid);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        SarifGuid other = (SarifGuid) obj;
        return Objects.equals(guid, other.guid);
    }
}
