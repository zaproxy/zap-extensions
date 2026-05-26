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

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVRecord;
import org.apache.commons.io.input.BOMInputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * The list of {@link BinRecord}s for credit card numbers.
 *
 * @since 1.0.0
 */
public final class BinList {

    private static final Logger LOGGER = LogManager.getLogger(BinList.class);
    private static final String BINLIST_FILE = "binlist-data.csv";

    private static final String COL_BIN = "BIN";
    private static final String COL_BRAND = "Brand";
    private static final String COL_CATEGORY = "Category";
    private static final String COL_ISSUER = "Issuer";

    private static BinList singleton;

    private Map<String, BinRecord> binMap;

    private BinList() {
        binMap = binMap();
    }

    public static BinList getSingleton() {
        if (singleton == null) {
            createSingleton();
        }
        return singleton;
    }

    private static synchronized void createSingleton() {
        if (singleton == null) {
            singleton = new BinList();
        }
    }

    private static Map<String, BinRecord> binMap() {
        Map<String, BinRecord> binMap = new HashMap<>();
        Iterable<CSVRecord> records;
        try (InputStream in = BinList.class.getResourceAsStream(BINLIST_FILE);
                BOMInputStream bomStream = BOMInputStream.builder().setInputStream(in).get();
                InputStreamReader inStream =
                        new InputStreamReader(bomStream, StandardCharsets.UTF_8)) {

            records =
                    CSVFormat.Builder.create()
                            .setHeader()
                            .setSkipHeaderRecord(true)
                            .get()
                            .parse(inStream)
                            .getRecords();
        } catch (NullPointerException | IOException e) {
            LOGGER.warn("Exception while loading: {}", BINLIST_FILE, e);
            return binMap;
        }

        for (CSVRecord rec : records) {
            binMap.put(
                    rec.get(COL_BIN),
                    new BinRecord(
                            rec.get(COL_BIN),
                            rec.get(COL_BRAND),
                            rec.get(COL_CATEGORY),
                            rec.get(COL_ISSUER)));
        }
        return binMap;
    }

    /**
     * Gets the {@code BinRecord} for the given (candidate) credit card number.
     *
     * @param candidate the candidate credit card number.
     * @return the {@code BinRecord}, or {@code null} if no match found.
     */
    public BinRecord get(String candidate) {
        BinRecord binRec = null;
        // Per https://github.com/venelinkochev/bin-list-data/ all Bins are 6 digits
        // Future iterations of the collection may include 8 digits Bins.
        if (candidate != null) {
            // Uncomment in the future when 8 digit bins are introduced in the data file.
            // if (candidate.length() >= 8) {
            //     binRec = binMap.get(candidate.substring(0, 8));
            // }
            if (binRec == null && candidate.length() >= 6) {
                binRec = binMap.get(candidate.substring(0, 6));
            }
        }
        return binRec;
    }
}
