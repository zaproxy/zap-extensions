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
package org.zaproxy.addon.retire.model;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonParseException;
import com.google.gson.reflect.TypeToken;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.HTMLElementName;
import net.htmlparser.jericho.Source;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.retire.Result;
import org.zaproxy.addon.retire.RetireUtil;

public class Repo {

    private static final String DONT_CHECK_NAME = "dont check";

    private final Map<String, RepoEntry> entries;

    public Repo(String resourcePath) throws IOException {
        try (InputStream in = Repo.class.getResourceAsStream(resourcePath);
                BufferedReader reader =
                        new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8)); ) {
            entries = createEntries(reader);
        }
    }

    public Repo(Path file) throws IOException {
        try (Reader reader = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
            entries = createEntries(reader);
        }
    }

    private static Map<String, RepoEntry> createEntries(Reader reader) throws IOException {
        try {
            Gson gson =
                    new GsonBuilder()
                            .registerTypeAdapter(Extractors.class, new ExtractorsTypeAdapter())
                            .create();
            Type repoMapType = new TypeToken<Map<String, RepoEntry>>() {}.getType();
            return gson.fromJson(reader, repoMapType);
        } catch (JsonParseException e) {
            throw new IOException("An error occurred while parsing the file.", e);
        }
    }

    public Result scanJS(HttpMessage msg) {
        return scanJS(msg, new Source(msg.getResponseBody().toString()));
    }

    /*
     * This is the top level function called from the scanner. It first checks if:
     * 1)Matching vulnerability is found in database for JS file URL, if YES return return HashSet of related info.
     * 2)Matching vulnerability is found in database for JS file name, if YES return return HashSet of related info.
     * 3)Matching vulnerability is found in database for JS file content, if YES return return HashSet of related info.
     * 4)Matching vulnerability is found in database for JS file hash, if YES return HashSet of related info .
     * 5)Return empty HashSet.
     */
    public Result scanJS(HttpMessage msg, Source source) {

        String uri = msg.getRequestHeader().getURI().toString();
        String fileName = RetireUtil.getFileName(msg.getRequestHeader().getURI());
        String content = getCleanContent(msg, source);
        Result result;

        // Check if included in don't check section
        HashMap<String, String> msginfo = new HashMap<>();
        msginfo.put(Extractors.TYPE_URI, uri);
        if (fileName != null) {
            msginfo.put(Extractors.TYPE_FILENAME, fileName);
        }
        msginfo.put(Extractors.TYPE_FILECONTENT, content);

        if (dontcheck(msginfo)) {
            return null;
        }

        result = scan(Extractors.TYPE_URI, uri);
        if (result != null) {
            return result;
        }

        if (fileName != null) {
            result = scan(Extractors.TYPE_FILENAME, fileName);
        }
        if (result != null) {
            return result;
        }

        result = scan(Extractors.TYPE_FILECONTENT, content);
        if (result != null) {
            return result;
        }

        String hash = RetireUtil.getHash(msg.getResponseBody().getBytes());
        return scanHash(hash);
    }

    private String getCleanContent(HttpMessage msg, Source source) {
        if (msg.getResponseHeader().isHtml()) {
            StringBuilder contents = new StringBuilder();
            for (Element scriptElement : source.getAllElements(HTMLElementName.SCRIPT)) {
                contents.append(scriptElement.toString());
                contents.append('\n');
            }
            return contents.toString();
        }
        return msg.getResponseBody().toString();
    }
    /*
     * This function computes the SHA 1 hash of the HTTP response body,
     * IF the hash matches that of an existing entry in the vulnerability database
     * corresponding info is returned.
     * ELSE an empty HashSet is returned.
     */
    private Result scanHash(String hash) {
        // Testable URL: https://ajax.googleapis.com/ajax/libs/dojo/1.1.1/dojo/dojo.js
        for (Map.Entry<String, RepoEntry> repoEntry : entries.entrySet()) {
            Map<String, String> hashes = repoEntry.getValue().getExtractors().getHashes();

            if (hashes != null && !hashes.isEmpty()) {
                for (Entry<String, String> hashItem : hashes.entrySet()) {
                    Map.Entry<String, String> hashEntry = hashItem;
                    List<Vulnerability> vulnerabilities = repoEntry.getValue().getVulnerabilities();

                    if (hash.equalsIgnoreCase(hashEntry.getKey())) {
                        Map<String, Set<String>> results =
                                isVersionVulnerable(vulnerabilities, hashEntry.getValue());
                        Result result =
                                new Result(repoEntry.getKey(), hashEntry.getValue(), results, "");
                        result.setOtherinfo(
                                Constant.messages.getString(
                                        "retire.rule.otherinfo", hashEntry.getKey()));
                        return result;
                    }
                }
            }
        }
        return null;
    }

    /*
     * This function takes in the criterion used for searching the vulnerability database.
     * The criterion can be:
     * FileName OR FileURL OR FileContent
     */
    private Result scan(String extractorType, String input) {
        // reading each entry for JS libraries in repo
        for (Map.Entry<String, RepoEntry> repoEntry : entries.entrySet()) {
            List<String> extractors = repoEntry.getValue().getExtractors().get(extractorType);

            // Reading all regexes with this extractor type (i.e. fileURI, fileName or fileContent
            // for
            // this particular JS library
            if (extractors != null && !extractors.isEmpty()) {
                ListIterator<String> iterator = extractors.listIterator();
                while (iterator.hasNext()) {
                    String regex = iterator.next();
                    if (regex != null) {
                        Pattern pattern = Pattern.compile(regex);
                        Matcher matcher = pattern.matcher(input);
                        if (matcher.find()) {
                            String versionString = matcher.group(1);

                            // Now try to determine if this version is vulnerable
                            List<Vulnerability> vulnerabilities =
                                    repoEntry.getValue().getVulnerabilities();
                            Map<String, Set<String>> results =
                                    isVersionVulnerable(vulnerabilities, versionString);
                            if (!results.isEmpty()) {
                                return new Result(
                                        repoEntry.getKey(),
                                        versionString,
                                        results,
                                        matcher.group(0));
                            }
                        }
                    }
                }
            }
        }
        return null;
    }

    /*
     * This function informs whether to scan a JS library at all. There are certain
     * libraries designated "dont check", so just ignore those.
     */
    private boolean dontcheck(HashMap<String, String> msginfo) {
        List<String> matches = null;

        RepoEntry dc = entries.get(DONT_CHECK_NAME);
        Extractors extractors = dc.getExtractors();

        // iterating over extractors
        for (Entry<String, String> criterion : msginfo.entrySet()) {
            matches = extractors.get(criterion.getKey());
            if (matches != null && !matches.isEmpty()) {
                Iterator<String> iterator = matches.iterator();
                while (iterator.hasNext()) {
                    String next = iterator.next();
                    if (next != null) {
                        Pattern p = Pattern.compile(next);
                        Matcher m = p.matcher(criterion.getValue());
                        // doing a match for each filename regex
                        if (m.find()) {
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }

    /*
     * This function depending on the vulnerability info of a passed JS library,
     * detects if the current version is vulnerable.
     * If YES returns the HashSet of vulnerability info.
     * else returns an empty HashSet.
     */
    private static Map<String, Set<String>> isVersionVulnerable(
            List<Vulnerability> vulnerabilities, String versionString) {
        // Do a match for each of the above vulnerabilities
        Map<String, Set<String>> results = new HashMap<>();
        ListIterator<Vulnerability> viterator = vulnerabilities.listIterator();
        Set<String> cve = new HashSet<>();
        Set<String> info = new HashSet<>();

        while (viterator.hasNext()) {
            boolean isVulnerable = false;
            Vulnerability vnext = viterator.next();

            if (vnext.hasAtOrAbove() && vnext.hasBelow()) {
                if (RetireUtil.isAtOrAbove(versionString, vnext.getAtOrAbove())
                        && !RetireUtil.isAtOrAbove(versionString, vnext.getBelow())) {
                    isVulnerable = true;
                }
            } else if (vnext.hasBelow()) {
                if (!RetireUtil.isAtOrAbove(versionString, vnext.getBelow())) {
                    isVulnerable = true;
                }
            } else if (vnext.hasAtOrAbove()) {
                if (RetireUtil.isAtOrAbove(versionString, vnext.getAtOrAbove())) {
                    isVulnerable = true;
                }
            }
            if (isVulnerable) {
                cve.addAll(vnext.getIdentifiers().getCve());
                results.put(Result.CVE, cve);
                info.addAll(vnext.getInfo());
                results.put(Result.INFO, info);
            }
        }
        return results;
    }
}
