/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
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
package org.zaproxy.zap.extension.ascanrules;

import com.strobel.decompiler.Decompiler;
import com.strobel.decompiler.DecompilerSettings;
import com.strobel.decompiler.PlainTextOutput;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.commons.lang.SystemUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractHostPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.model.Vulnerabilities;
import org.zaproxy.zap.model.Vulnerability;

/**
 * a scanner that looks for Java classes disclosed via the WEB-INF folder and that decompiles them
 * to give the Java source code. The scanner also looks for easy pickings in the form of properties
 * files loaded by the Java class.
 *
 * @author 70pointer
 */
public class SourceCodeDisclosureWebInfScanRule extends AbstractHostPlugin {

    // TODO: for imported classes that we do not find in the classes folder, map to jar file names,
    // which we might find in WEB-INF/lib/ ?
    // TODO: pull referenced properties files from WEB-INF?

    /** the set of files that commonly occur in the WEB-INF folder */
    private static final List<String> WEBINF_FILES =
            new LinkedList<String>(
                    Arrays.asList(
                            new String[] {
                                "web.xml", "applicationContext.xml" // for Spring
                            }));
    /**
     * match on Java class names (including the package info) we're "flexible" on the package names
     * and class names containing uppercase versus lowercase, by necessity.
     */
    private static final Pattern JAVA_CLASSNAME_PATTERN =
            Pattern.compile("[0-9a-zA-Z_.]+\\.[a-zA-Z0-9_]+");

    /** match on imports in the decompiled Java source, to find the names of more classes to pull */
    private static final Pattern JAVA_IMPORT_CLASSNAME_PATTERN =
            Pattern.compile("^import\\s+([0-9a-zA-Z_.]+\\.[a-zA-Z0-9_]+);", Pattern.MULTILINE);

    /** find references to properties files in the Java source code */
    private static final Pattern PROPERTIES_FILE_PATTERN =
            Pattern.compile("\"([/a-zA-Z0-9_-]+.properties)\"");

    /**
     * details of the vulnerability which we are attempting to find 34 = Predictable Resource
     * Location
     */
    private static final Vulnerability vuln = Vulnerabilities.getVulnerability("wasc_34");

    private static final Logger log =
            LogManager.getLogger(SourceCodeDisclosureWebInfScanRule.class);

    @Override
    public int getId() {
        return 10045;
    }

    @Override
    public String getName() {
        return Constant.messages.getString("ascanrules.sourcecodedisclosurewebinf.name");
    }

    @Override
    public String getDescription() {
        if (vuln != null) {
            return vuln.getDescription();
        }
        return "Failed to load vulnerability description from file";
    }

    @Override
    public int getCategory() {
        return Category.INFO_GATHER;
    }

    @Override
    public String getSolution() {
        if (vuln != null) {
            return vuln.getSolution();
        }
        return "Failed to load vulnerability solution from file";
    }

    @Override
    public String getReference() {
        if (vuln != null) {
            StringBuilder sb = new StringBuilder();
            for (String ref : vuln.getReferences()) {
                if (sb.length() > 0) {
                    sb.append('\n');
                }
                sb.append(ref);
            }
            return sb.toString();
        }
        return "Failed to load vulnerability reference from file";
    }

    @Override
    public void init() {
        // Does not work with Java 9+
        // https://github.com/zaproxy/zaproxy/issues/4038
        if (SystemUtils.isJavaVersionAtLeast(1.9f)) {
            getParent()
                    .pluginSkipped(
                            this,
                            Constant.messages.getString(
                                    "ascanrules.sourcecodedisclosurewebinf.skipJava9"));
        }
    }

    @Override
    public void scan() {
        try {
            URI originalURI = getBaseMsg().getRequestHeader().getURI();
            List<String> javaClassesFound = new LinkedList<String>();
            List<String> javaClassesHandled = new LinkedList<String>();

            // Pass 1: thru each of the WEB-INF files, looking for class names
            for (String filename : WEBINF_FILES) {

                HttpMessage webinffilemsg =
                        new HttpMessage(
                                new URI(
                                        originalURI.getScheme()
                                                + "://"
                                                + originalURI.getAuthority()
                                                + "/WEB-INF/"
                                                + filename,
                                        true));
                sendAndReceive(webinffilemsg, false); // do not follow redirects
                String body = new String(webinffilemsg.getResponseBody().getBytes());
                Matcher matcher = JAVA_CLASSNAME_PATTERN.matcher(body);
                while (matcher.find()) {
                    // we have a possible class *name*.
                    // Next: See if the class file lives in the expected location in the WEB-INF
                    // folder
                    // skip Java built-in classes
                    String classname = matcher.group();
                    if (!classname.startsWith("java.")
                            && !classname.startsWith("javax.")
                            && !javaClassesFound.contains(classname)) {
                        javaClassesFound.add(classname);
                    }
                }
            }

            // for each class name found, try download the actual class file..
            // for ( String classname: javaClassesFound) {
            while (javaClassesFound.size() > 0) {
                String classname = javaClassesFound.get(0);
                URI classURI = getClassURI(originalURI, classname);
                log.debug("Looking for Class file: {}", classURI.getURI());

                HttpMessage classfilemsg = new HttpMessage(classURI);
                sendAndReceive(classfilemsg, false); // do not follow redirects
                if (isPage200(classfilemsg)) {
                    // to decompile the class file, we need to write it to disk..
                    // under the current version of the library, at least
                    File classFile = null;
                    try {
                        classFile = File.createTempFile("zap", ".class");
                        classFile.deleteOnExit();
                        OutputStream fos = new FileOutputStream(classFile);
                        fos.write(classfilemsg.getResponseBody().getBytes());
                        fos.close();

                        // now decompile it
                        DecompilerSettings decompilerSettings = new DecompilerSettings();

                        // set some options so that we can better parse the output, to get the names
                        // of more classes..
                        decompilerSettings.setForceExplicitImports(true);
                        decompilerSettings.setForceExplicitTypeArguments(true);

                        PlainTextOutput decompiledText = new PlainTextOutput();
                        Decompiler.decompile(
                                classFile.getAbsolutePath(), decompiledText, decompilerSettings);
                        String javaSourceCode = decompiledText.toString();

                        if (javaSourceCode.startsWith("!!! ERROR: Failed to load class")) {
                            // Not a Java class file...
                            javaClassesFound.remove(classname);
                            javaClassesHandled.add(classname);
                            continue;
                        }

                        log.debug("Source Code Disclosure alert for: {}", classname);

                        newAlert()
                                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                                .setName(
                                        Constant.messages.getString(
                                                "ascanrules.sourcecodedisclosurewebinf.name"))
                                .setDescription(
                                        Constant.messages.getString(
                                                "ascanrules.sourcecodedisclosurewebinf.desc"))
                                .setOtherInfo(javaSourceCode)
                                .setSolution(
                                        Constant.messages.getString(
                                                "ascanrules.sourcecodedisclosurewebinf.soln"))
                                .setMessage(classfilemsg)
                                .raise();

                        // and add the referenced classes to the list of classes to look for!
                        // so that we catch as much source code as possible.
                        Matcher importMatcher =
                                JAVA_IMPORT_CLASSNAME_PATTERN.matcher(javaSourceCode);
                        while (importMatcher.find()) {
                            // we have another possible class name.
                            // Next: See if the class file lives in the expected location in the
                            // WEB-INF folder
                            String importClassname = importMatcher.group(1);

                            if ((!javaClassesFound.contains(importClassname))
                                    && (!javaClassesHandled.contains(importClassname))) {
                                javaClassesFound.add(importClassname);
                            }
                        }

                        // attempt to find properties files within the Java source, and try get them
                        Matcher propsFileMatcher = PROPERTIES_FILE_PATTERN.matcher(javaSourceCode);
                        while (propsFileMatcher.find()) {
                            String propsFilename = propsFileMatcher.group(1);
                            log.debug("Found props file: {}", propsFilename);

                            URI propsFileURI = getPropsFileURI(originalURI, propsFilename);
                            HttpMessage propsfilemsg = new HttpMessage(propsFileURI);
                            sendAndReceive(propsfilemsg, false); // do not follow redirects
                            if (isPage200(propsfilemsg)) {
                                // Holy sheet.. we found a properties file
                                newAlert()
                                        .setConfidence(Alert.CONFIDENCE_MEDIUM)
                                        .setName(
                                                Constant.messages.getString(
                                                        "ascanrules.sourcecodedisclosurewebinf.propertiesfile.name"))
                                        .setDescription(
                                                Constant.messages.getString(
                                                        "ascanrules.sourcecodedisclosurewebinf.propertiesfile.desc"))
                                        .setOtherInfo(
                                                Constant.messages.getString(
                                                        "ascanrules.sourcecodedisclosurewebinf.propertiesfile.extrainfo",
                                                        classURI))
                                        .setSolution(
                                                Constant.messages.getString(
                                                        "ascanrules.sourcecodedisclosurewebinf.propertiesfile.soln"))
                                        .setMessage(propsfilemsg)
                                        .raise();
                            }
                        }
                        // do not return at this point.. there may be multiple classes referenced.
                        // We want to see as many of them as possible.
                    } finally {
                        // delete the temp file.
                        // this will be deleted when the VM is shut down anyway, but just in case!
                        if (classFile != null) classFile.delete();
                    }
                }
                // remove the class from the set to handle, and add it to the list of classes
                // handled
                javaClassesFound.remove(classname);
                javaClassesHandled.add(classname);
            }
        } catch (Exception e) {
            log.error(
                    "Error scanning a Host for Source Code Disclosure via the WEB-INF folder: {}",
                    e.getMessage(),
                    e);
        }
    }

    /**
     * gets a candidate URI for a given class path.
     *
     * @param classname
     * @return
     * @throws URIException
     */
    private URI getClassURI(URI hostURI, String classname) throws URIException {
        return new URI(
                hostURI.getScheme()
                        + "://"
                        + hostURI.getAuthority()
                        + "/WEB-INF/classes/"
                        + classname.replaceAll("\\.", "/")
                        + ".class",
                false);
    }

    private URI getPropsFileURI(URI hostURI, String propsfilename) throws URIException {
        return new URI(
                hostURI.getScheme()
                        + "://"
                        + hostURI.getAuthority()
                        + "/WEB-INF/classes/"
                        + propsfilename,
                false);
    }

    @Override
    public int getRisk() {
        return Alert.RISK_HIGH;
    }

    @Override
    public int getCweId() {
        return 541; // Information Exposure Through Include Source Code
    }

    @Override
    public int getWascId() {
        return 34; // Predictable Resource Location
    }
}
