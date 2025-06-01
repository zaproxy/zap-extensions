/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2012 The ZAP Development Team
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
package org.zaproxy.zap.extension.tokengen;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.zaproxy.zap.extension.tokengen.TokenAnalysisTestResult.Result;

public class CharacterFrequencyMap {
    // Rename to something more generic??

    private static String DEC_CHRS = "-.0123456789";
    private static String HEX_CHRS = "0123456789ABCDEFabcdef";

    private List<String> tokens = new ArrayList<>();
    private Map<Character, Integer> map = new HashMap<>();
    private char lowestChar = Character.MAX_VALUE;
    private char highestChar = Character.MIN_VALUE;
    private boolean allDec = true;
    private boolean allHex = true;
    private BigInteger maxNumber = BigInteger.ZERO;
    private boolean exceededLong = false;
    private int minLength = Integer.MAX_VALUE;
    private int maxLength = 0;
    private Map<Integer, Set<Character>> charsPerPosn = new HashMap<>();
    private Set<Character> allChrs = new HashSet<>();

    public void addToken(String token) {
        tokens.add(token);
        if (token.length() > maxLength) {
            maxLength = token.length();
        }
        if (token.length() < minLength) {
            minLength = token.length();
        }
        int index = 0;
        for (char chr : token.toCharArray()) {
            allChrs.add(chr);
            if (charsPerPosn.get(index) == null) {
                charsPerPosn.put(index, new HashSet<>());
            }
            charsPerPosn.get(index).add(chr);
            Integer intVal = map.get(chr);
            if (intVal == null) {
                intVal = Integer.valueOf(0);
                if (chr < lowestChar) {
                    lowestChar = chr;
                }
                if (chr > highestChar) {
                    highestChar = chr;
                }
            }
            map.put(chr, intVal + 1);

            if (DEC_CHRS.indexOf(chr) < 0) {
                allDec = false;
            }
            if (HEX_CHRS.indexOf(chr) < 0) {
                allHex = false;
            }
            index++;
        }
        if (allDec) {
            try {
                maxNumber = maxNumber.max(new BigInteger(token, 10));
            } catch (NumberFormatException e) {
                exceededLong = true;
            }
        }
        if (allHex) {
            try {
                maxNumber = maxNumber.max(new BigInteger(token, 16));
            } catch (NumberFormatException e) {
                exceededLong = true;
            }
        }
    }

    public double log2(double i) {
        return Math.log(i) / Math.log(2);
    }

    public double getMaxTheoreticalEntropy() {
        double entropy = 0;
        Iterator<Entry<Integer, Set<Character>>> iter = charsPerPosn.entrySet().iterator();
        while (iter.hasNext()) {
            Entry<Integer, Set<Character>> cpp = iter.next();
            entropy += log2(cpp.getValue().size());
        }
        return entropy;
    }

    private int mdev(int i) {
        // TODO where does stompy get this formula from??
        return (int) (500 / Math.pow(i, 0.375) + 5);
    }

    public TokenAnalysisTestResult checkCharacterUniformity() {
        TokenAnalysisTestResult result =
                new TokenAnalysisTestResult(TokenAnalysisTestResult.Type.CHR_UNIFORMITY);
        List<String> details = new ArrayList<>();
        List<String> issues = new ArrayList<>();
        int mid = numberOfChars() != 0 ? (size() / numberOfChars()) : 0;
        int mdev = mdev(numberOfChars());
        int min = mid - mdev;
        int max = mid + mdev;

        for (int i = 0; i < maxLength; i++) {
            StringBuilder sb = new StringBuilder();
            sb.append("Col ");
            sb.append(i);
            for (char c : allChrs) {
                int instantsOfChr = 0;

                // TODO handle decs as special case?
                for (String token : tokens) {
                    if (token != null && token.length() > i && token.charAt(i) == c) {
                        instantsOfChr++;
                    }
                }
                sb.append(" ");
                sb.append(c);
                sb.append(":");
                sb.append(instantsOfChr);
                if (instantsOfChr > max) {
                    issues.add(
                            "Column "
                                    + i
                                    + " Character "
                                    + c
                                    + " appears "
                                    + instantsOfChr
                                    + " times: more than expected ("
                                    + max
                                    + ")");
                } else if (instantsOfChr < min) {
                    issues.add(
                            "Column "
                                    + i
                                    + " Character "
                                    + c
                                    + " appears "
                                    + instantsOfChr
                                    + " times: less than expected ("
                                    + min
                                    + ")");
                }
            }
            details.add(sb.toString());
        }

        if (maxLength == 0) {
            issues.add("Tokens have zero characters.");
        }

        result.setResult(issues.isEmpty() ? Result.PASS : Result.FAIL);
        result.setFailures(issues);
        result.setDetails(details);
        return result;
    }

    public void hack() {
        // TODO
        // Stompy gives:		Java
        // cpp = 16				 61		ok
        // mid = 78.125..		 39			- probably ok, as its using 20000 vs 10000 ??
        // dev = 181.776..		181 	ok
        // min = -103			-142	~	ok?
        // max = 258			220		~	ok?
        //

        for (int i = 0; i < maxLength; i++) {
            int chrsAtI = charsPerPosn.get(i).size();
            int mid = tokens.size() / chrsAtI / chrsAtI;
            int mdev = mdev(chrsAtI);
            int min = mid - mdev;
            int max = mid + mdev;

            System.out.println("cpp = " + chrsAtI);
            System.out.println("Mid = " + mid);
            System.out.println("Mdv = " + mdev);
            System.out.println("Min = " + min);
            System.out.println("Max = " + max);
        }
    }

    public TokenAnalysisTestResult checkCharacterTransitions() {
        TokenAnalysisTestResult result =
                new TokenAnalysisTestResult(TokenAnalysisTestResult.Type.CHR_TRANSITIONS);
        Result res = Result.PASS;
        List<String> details = new ArrayList<>();
        List<String> issues = new ArrayList<>();

        for (int i = 0; i < maxLength; i++) {
            // Loop through token places
            StringBuilder sb = new StringBuilder();
            sb.append("Col ");
            sb.append(i);

            int[][] trans = new int[256][256];
            int chrsAtI = charsPerPosn.get(i).size();
            int mid = tokens.size() / chrsAtI / chrsAtI;
            int mdev = mdev(chrsAtI);
            int min = mid - mdev;
            int max = mid + mdev;

            for (String token : tokens) {
                int j = i + 1;
                if (j >= maxLength) {
                    j = 0;
                }
                if (i < token.length()) {
                    char c1 = token.charAt(i);
                    if (j < token.length()) {
                        char c2 = token.charAt(j);
                        trans[c1][c2]++;
                    }
                }
            }
            for (int x = 0; x < 256; x++) {
                for (int y = 0; y < 256; y++) {
                    if (trans[x][y] > 0) {
                        sb.append(" ");
                        sb.append(((char) x));
                        sb.append("->");
                        sb.append(((char) y));
                        sb.append("=");
                        sb.append(trans[x][y]);
                        if (trans[x][y] > max) {
                            issues.add(
                                    "Column "
                                            + i
                                            + " "
                                            + ((char) x)
                                            + " -> "
                                            + ((char) y)
                                            + " = "
                                            + trans[x][y]
                                            + " > than expected ("
                                            + max
                                            + ")");
                            res = Result.FAIL;
                        }
                        if (trans[x][y] < min) {
                            issues.add(
                                    "Column "
                                            + i
                                            + " "
                                            + ((char) x)
                                            + " -> "
                                            + ((char) y)
                                            + " = "
                                            + trans[x][y]
                                            + " < than expected ("
                                            + min
                                            + ")");
                            res = Result.FAIL;
                        }
                    }
                }
            }
            details.add(sb.toString());
        }

        result.setResult(res);
        result.setFailures(issues);
        result.setDetails(details);
        return result;
    }

    public int getFrequency(char chr) {
        Integer i = map.get(chr);
        if (i == null) {
            return 0;
        }
        return i;
    }

    public char getLowestChar() {
        return lowestChar;
    }

    public char getHighestChar() {
        return highestChar;
    }

    public boolean isAllHex() {
        return allHex;
    }

    public boolean isAllDecimal() {
        return allDec;
    }

    public BigInteger getMaxNumber() {
        return maxNumber;
    }

    public boolean isExceededLong() {
        return exceededLong;
    }

    public List<String> getTokens() {
        return tokens;
    }

    public BigInteger getBigIntegerToken(int index) {
        if (index >= tokens.size()) {
            return null;
        }
        if (allDec) {
            return new BigInteger(this.tokens.get(index), 10);

        } else if (allHex) {
            return new BigInteger(this.tokens.get(index), 16);
        }
        return new BigInteger(this.tokens.get(index).getBytes());
    }

    public byte[] getByteArrayToken(int index) throws DecoderException {
        if (index >= tokens.size()) {
            return null;
        }
        if (allDec) {
            return (new BigInteger(this.tokens.get(index), 10)).toByteArray();

        } else if (allHex) {
            return Hex.decodeHex(this.tokens.get(index).toCharArray());
        }
        return this.tokens.get(index).getBytes();
        // TODO This ok now?
        /*
        //return this.tokens.get(index).getBytes();


        return Hex.decodeHex(this.tokens.get(index).toCharArray());
        / *
        String s = this.tokens.get(index);
        int len = s.length();
           byte[] data = new byte[len / 2];
           for (int i = 0; i < len; i += 2) {
               data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                    + Character.digit(s.charAt(i+1), 16));
           }
           return data;
        */

    }

    public void save(File file) throws IOException {
        try (BufferedWriter out = new BufferedWriter(new FileWriter(file))) {
            for (String token : tokens) {
                out.write(token + "\n");
            }
        }
    }

    public void load(File file) throws IOException {
        try (BufferedReader in = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = in.readLine()) != null) {
                this.addToken(line.trim());
            }
        }
    }

    public int size() {
        return this.tokens.size();
    }

    public int numberOfChars() {
        return allChrs.size();
    }
}
