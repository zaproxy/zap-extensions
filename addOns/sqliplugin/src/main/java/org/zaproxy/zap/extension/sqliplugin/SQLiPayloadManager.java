/*
 * Derivative Work based upon SQLMap source code implementation
 *
 * Copyright (c) 2006-2012 sqlmap developers (http://sqlmap.org/)
 * Bernardo Damele Assumpcao Guimaraes, Miroslav Stampar.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
package org.zaproxy.zap.extension.sqliplugin;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jdom2.Document;
import org.jdom2.Element;
import org.jdom2.JDOMException;
import org.jdom2.input.SAXBuilder;

/**
 * Manager class for the overall boundaries and testing plugins. Load element definitions from an
 * XML file and give back all needed functionalities to use them inside an active scanner.
 *
 * @author yhawke (2013)
 */
public class SQLiPayloadManager {

    // PAYLOAD CONSTANTS
    public static final int TECHNIQUE_BOOLEAN = 1;
    public static final int TECHNIQUE_ERROR = 2;
    public static final int TECHNIQUE_INLINE = 3;
    public static final int TECHNIQUE_STACKED = 4;
    public static final int TECHNIQUE_TIME = 5;
    public static final int TECHNIQUE_UNION = 6;

    // Map for technique retrieval
    static final Map<Integer, String> SQLI_TECHNIQUES = new HashMap<>();

    static {
        SQLI_TECHNIQUES.put(TECHNIQUE_BOOLEAN, "boolean-based blind");
        SQLI_TECHNIQUES.put(TECHNIQUE_ERROR, "error-based");
        SQLI_TECHNIQUES.put(TECHNIQUE_INLINE, "inline query");
        SQLI_TECHNIQUES.put(TECHNIQUE_STACKED, "stacked queries");
        SQLI_TECHNIQUES.put(TECHNIQUE_TIME, "AND/OR time-based blind");
        SQLI_TECHNIQUES.put(TECHNIQUE_UNION, "UNION query");
    }

    // PAYLOAD ORIGINAL VALUE MANAGEMENT CONSTANTS
    public static final int WHERE_ORIGINAL = 1;
    public static final int WHERE_NEGATIVE = 2;
    public static final int WHERE_REPLACE = 3;

    private static final Random RAND = new Random();
    // Initialization elements for payload generation
    public static final String charsStart = ":" + randomString(3, true, null) + ":";
    public static final String charsStop = ":" + randomString(3, true, null) + ":";
    public static final String charsAt = ":" + randomString(4, true, null) + ":";
    public static final String charsSpace = ":" + randomString(4, true, null) + ":";
    public static final String charsDollar = ":" + randomString(4, true, null) + ":";
    public static final String charsHash = ":" + randomString(4, true, null) + ":";
    public static final String charsDelimiter = randomString(6, true, null);

    private static final String BOUNDARY_FILE = "resources/boundaries.xml";
    private static final String PAYLOAD_FILE = "resources/payloads.xml";
    private static final String TAG_BOUNDARY = "boundary";
    private static final String TAG_TEST = "test";

    private static final String PAYLOAD_DELIMITER = "\\x00";
    // Regular expression used for replacing non-alphanum characters
    private static final String REFLECTED_REPLACEMENT_REGEX = ".+?";
    // Regular expression used for replacing border non-alphanum characters
    private static final String REFLECTED_BORDER_REGEX = "[^A-Za-z]+";
    // Maximum number of alpha-numerical parts in reflected regex (for speed purposes)
    private static final int REFLECTED_MAX_REGEX_PARTS = 10;
    // Mark used for replacement of reflected values
    public static final String REFLECTED_VALUE_MARKER = "__REFLECTED_VALUE__";

    private List<SQLiBoundary> boundaries;
    private List<SQLiTest> tests;

    private static final Logger log = LogManager.getLogger(SQLiPayloadManager.class);

    // Singleton variable
    private static SQLiPayloadManager instance;

    /**
     * Gets back the singleton of this KB object
     *
     * @return an instance of the payload database
     */
    public static SQLiPayloadManager getInstance() {
        if (instance == null) {
            try {
                instance = new SQLiPayloadManager();

            } catch (IOException | JDOMException ex) {
                log.error("Cannot initialize the Payload database instance", ex);
            }
        }

        return instance;
    }

    /** Inner contructor used to create the Singleton */
    private SQLiPayloadManager() throws IOException, JDOMException {
        boundaries = new ArrayList<>();
        tests = new ArrayList<>();

        // Load all boundaries from resources
        SAXBuilder builder = new SAXBuilder();
        builder.setExpandEntities(false);
        builder.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        builder.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        builder.setFeature("http://xml.org/sax/features/external-general-entities", false);
        InputStream is = this.getClass().getResourceAsStream(BOUNDARY_FILE);
        Document doc = builder.build(is);
        Element rootNode = doc.getRootElement();

        // now we have the <root> tag indexed so we can
        // go ahead for boundaries
        for (Object obj : rootNode.getChildren(TAG_BOUNDARY)) {
            boundaries.add(new SQLiBoundary((Element) obj));
        }

        // Log current execution
        // log.info("Loaded {} boundary elements", boundaries.size());
        is.close();

        // Load all payloads from resources
        is = this.getClass().getResourceAsStream(PAYLOAD_FILE);
        doc = builder.build(is);
        rootNode = doc.getRootElement();

        for (Object obj : rootNode.getChildren(TAG_TEST)) {
            tests.add(new SQLiTest((Element) obj));
        }

        // Log current execution
        // log.info("Loaded {} payload elements", tests.size());
        is.close();
    }

    /**
     * Get a list of all defined boundaries
     *
     * @return a list of boundary elements
     */
    public List<SQLiBoundary> getBoundaries() {
        return boundaries;
    }

    /**
     * Get a list of all defined tests
     *
     * @return a list of test elements
     */
    public List<SQLiTest> getTests() {
        return tests;
    }

    /**
     * Get a random integer value of lenght digits
     *
     * @param length the number of digits of this integer
     * @return the integer value
     */
    public static String randomInt(int length) {
        StringBuilder result = new StringBuilder();
        result.append((char) (RAND.nextInt(9) + '1'));

        for (int i = 1; i < length; i++) {
            result.append((char) (RAND.nextInt(10) + '0'));
        }

        return result.toString();
    }

    /**
     * Get a random integer value of 4 digits
     *
     * @return the integer value
     */
    public static String randomInt() {
        return randomInt(4);
    }

    /**
     * Get a randomly built string with exactly lenght chars
     *
     * @param length the number of chars of this string
     * @param lowerCase get only lowercase chars
     * @param alphabet set the alphabet to use
     * @return a string element containing exactly "lenght" characters
     */
    public static String randomString(int length, boolean lowerCase, String alphabet) {
        StringBuilder result = new StringBuilder();

        if (alphabet == null) {
            alphabet = "abcdefghijklmnopqrstuvwxyz";
            if (!lowerCase) {
                alphabet += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            }
        }

        for (int i = 0; i < length; i++) {
            result.append(alphabet.charAt(RAND.nextInt(alphabet.length())));
        }

        return result.toString();
    }

    /**
     * Get a randomly built string with exactly 4 elements both uppercase and lowercase.
     *
     * @return a string element containing exactly 4 characters
     */
    public static String randomString() {
        return randomString(4, false, null);
    }

    /**
     * Get regex for reflective payload management: replace every non alphanumeric character with a
     * specific regex
     *
     * @param value the original payload
     * @return a string regex where each non-alphabetic char has been substituted with a generic
     *     regex
     */
    private static String buildReflectiveRegex(String value) {
        StringBuilder builder = new StringBuilder();
        boolean doRegex = true;

        for (char c : value.toCharArray()) {
            if (((c >= 'A') && (c <= 'Z'))
                    || ((c >= 'a') && (c <= 'z'))
                    || ((c >= '0') && (c <= '9'))) {

                builder.append(c);
                doRegex = true;

            } else if (doRegex) {
                builder.append(REFLECTED_REPLACEMENT_REGEX);
                doRegex = false;
            }
        }

        return builder.toString();
    }

    /**
     * Neutralizes reflective values in a given content based on a payload (e.g. ..search.php?q=1
     * AND 1=2 --> "...searching for <b>1%20AND%201%3D2</b>..." --> "...searching for
     * <b>__REFLECTED_VALUE__</b>...")
     *
     * @param content the content that need to be normalized
     * @param payload the payload that need to be neutralized
     * @return a normalized content free from all reflective values
     */
    public static String removeReflectiveValues(String content, String payload) {
        String retVal = content;

        if ((content != null) && (payload != null)) {
            String decodedPayload = payload.replace(PAYLOAD_DELIMITER, "");
            // decodedPayload = AbstractPlugin.getURLDecode(decodedPayload);
            String regex = buildReflectiveRegex(decodedPayload);

            if (!regex.equals(decodedPayload)) {
                List<String> parts = new ArrayList<>();
                int sidx = 0;
                int eidx;

                while ((eidx = regex.indexOf(REFLECTED_REPLACEMENT_REGEX, sidx)) != -1) {
                    parts.add(regex.substring(sidx, eidx));
                    sidx = eidx + REFLECTED_REPLACEMENT_REGEX.length();
                }

                // fast optimization check
                boolean allIncluded = true;

                for (String part : parts) {
                    if (!content.toLowerCase().contains(part.toLowerCase())) {
                        allIncluded = false;
                        break;
                    }
                }

                if (allIncluded) {
                    // dummy approach
                    retVal = content.replace(decodedPayload, REFLECTED_VALUE_MARKER);

                    // preventing CPU hogs
                    if (parts.size() > REFLECTED_MAX_REGEX_PARTS) {
                        StringBuilder tmpBuilder = new StringBuilder();
                        boolean isFirst = true;

                        // Build first part of the regex
                        for (int i = 0; i < REFLECTED_MAX_REGEX_PARTS / 2; i++) {
                            if (isFirst) {
                                isFirst = false;

                            } else {
                                tmpBuilder.append(REFLECTED_REPLACEMENT_REGEX);
                            }

                            tmpBuilder.append(parts.get(i));
                        }

                        // Build second part of the regex
                        for (int i = parts.size() - REFLECTED_MAX_REGEX_PARTS / 2;
                                i < parts.size();
                                i++) {
                            tmpBuilder.append(REFLECTED_REPLACEMENT_REGEX);
                            tmpBuilder.append(parts.get(i));
                        }

                        regex = tmpBuilder.toString();
                    }

                    regex =
                            (regex.startsWith(REFLECTED_REPLACEMENT_REGEX))
                                    ? REFLECTED_BORDER_REGEX
                                            + regex.substring(REFLECTED_REPLACEMENT_REGEX.length())
                                    : "\\b" + regex;

                    regex =
                            (regex.endsWith(REFLECTED_REPLACEMENT_REGEX))
                                    ? regex.substring(
                                                    0,
                                                    regex.length()
                                                            - REFLECTED_REPLACEMENT_REGEX.length())
                                            + REFLECTED_BORDER_REGEX
                                    : regex + "\\b";

                    retVal = retVal.replaceAll("(?i)" + regex, REFLECTED_VALUE_MARKER);

                    // TO BE VERIFIED...
                    // parts = filter(None, regex.split(REFLECTED_REPLACEMENT_REGEX))
                    // if len(parts) > 2:
                    //    regex = REFLECTED_REPLACEMENT_REGEX.join(parts[1:])
                    //    retVal = re.sub(r"(?i)\\b%s\\b" % regex, REFLECTED_VALUE_MARKER, retVal)
                }
            }
        }

        return retVal;
    }
}
