/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.addon.retire.model;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.hasEntry;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.Test;

/** Unit test for {@link Repo}. */
class RepoUnitTest {
    @Test
    void shouldReadEmptyRepo() throws IOException {
        // Given
        Reader data = reader("repo-empty.json");
        // When
        Map<String, RepoEntry> entries = Repo.createEntries(data);
        // Then
        assertThat(entries.size(), is(0));
    }

    @Test
    void shouldReadEmptyLib() throws IOException {
        // Given
        Reader data = reader("lib-empty.json");
        // When
        Map<String, RepoEntry> entries = Repo.createEntries(data);
        // Then
        assertThat(entries.size(), is(1));
        RepoEntry entry = entries.get("lib");
        assertThat(entry, is(notNullValue()));
        assertThat(entry.getVulnerabilities(), is(nullValue()));
        assertThat(entry.getExtractors(), is(nullValue()));
    }

    @Test
    void shouldReadLibWithNoVulnerabilities() throws IOException {
        // Given
        Reader data = reader("vulns-empty.json");
        // When
        Map<String, RepoEntry> entries = Repo.createEntries(data);
        // Then
        assertThat(entries.size(), is(1));
        RepoEntry entry = entries.get("lib");
        assertThat(entry.getVulnerabilities(), is(empty()));
    }

    @Test
    void shouldReadLibWithVulnerabilities() throws IOException {
        // Given
        Reader data = reader("vulns-all.json");
        // When
        Map<String, RepoEntry> entries = Repo.createEntries(data);
        // Then
        assertThat(entries.size(), is(1));
        RepoEntry entry = entries.get("lib");
        List<Vulnerability> vulns = entry.getVulnerabilities();
        assertThat(vulns, hasSize(1));
        Vulnerability vuln = vulns.get(0);
        assertThat(vuln, is(notNullValue()));
        assertThat(vuln.getAtOrAbove(), is("atorabove"));
        assertThat(vuln.getBelow(), is("below"));
        Identifiers identifiers = vuln.getIdentifiers();
        assertThat(identifiers.getBug(), is("bug"));
        assertThat(identifiers.getCve(), contains("cve 1", "cve 2"));
        assertThat(identifiers.getSummary(), is("summary"));
        assertThat(vuln.getInfo(), contains("info 1", "info 2"));
        assertThat(vuln.getSeverity(), is("severity"));
    }

    @Test
    void shouldReadLibWithNoExtractors() throws IOException {
        // Given
        Reader data = reader("extractors-empty.json");
        // When
        Map<String, RepoEntry> entries = Repo.createEntries(data);
        // Then
        assertThat(entries.size(), is(1));
        RepoEntry entry = entries.get("lib");
        Extractors extractors = entry.getExtractors();
        assertThat(extractors, is(notNullValue()));
        assertThat(extractors.getFilecontent(), is(nullValue()));
        assertThat(extractors.getFilename(), is(nullValue()));
        assertThat(extractors.getFunc(), is(nullValue()));
        assertThat(extractors.getHashes(), is(notNullValue()));
        assertThat(extractors.getHashes().size(), is(0));
        assertThat(extractors.getUri(), is(nullValue()));
    }

    @Test
    void shouldReadLibWithAllExtractors() throws IOException {
        // Given
        Reader data = reader("extractors-all.json");
        // When
        Map<String, RepoEntry> entries = Repo.createEntries(data);
        // Then
        assertThat(entries.size(), is(1));
        RepoEntry entry = entries.get("lib");
        Extractors extractors = entry.getExtractors();
        assertThat(extractors, is(notNullValue()));
        assertThat(
                extractors.getFilecontent(),
                contains("filecontent 1", "filecontent 2", "[0-9][0-9a-z._\\-]+?"));
        assertThat(
                extractors.getFilename(),
                contains("filename 1", "filename 2", "[0-9][0-9a-z._\\-]+?"));
        assertThat(extractors.getFunc(), contains("func 1", "func 2", "[0-9][0-9a-z._\\-]+?"));
        assertThat(extractors.getHashes(), is(notNullValue()));
        assertThat(extractors.getHashes().size(), is(3));
        assertThat(
                extractors.getHashes(),
                allOf(
                        hasEntry("hash 1", "version 1"),
                        hasEntry("hash 2", "version 2"),
                        hasEntry("§§version§§", "§§version§§")));
        assertThat(extractors.getUri(), contains("uri 1", "uri 2", "[0-9][0-9a-z._\\-]+?"));
    }

    private static Reader reader(String fileName) throws IOException {
        String content;
        try (var is = RepoUnitTest.class.getResourceAsStream("samples/" + fileName)) {
            content = IOUtils.toString(is, StandardCharsets.UTF_8);
        }
        return new StringReader(content);
    }
}
