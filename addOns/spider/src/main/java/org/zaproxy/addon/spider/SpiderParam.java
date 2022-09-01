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
package org.zaproxy.addon.spider;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;
import org.apache.commons.configuration.ConversionException;
import org.apache.commons.configuration.HierarchicalConfiguration;
import org.apache.commons.httpclient.URI;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.zaproxy.addon.spider.internal.IrrelevantParameter;
import org.zaproxy.zap.common.VersionedAbstractParam;
import org.zaproxy.zap.extension.api.ZapApiIgnore;
import org.zaproxy.zap.extension.httpsessions.ExtensionHttpSessions;

/** The SpiderParam wraps all the parameters that are given to the spider. */
public class SpiderParam extends VersionedAbstractParam {

    /**
     * The value that indicates that the crawl depth is unlimited.
     *
     * @see #setMaxDepth(int)
     */
    public static final int UNLIMITED_DEPTH = 0;

    /**
     * The current version of the configurations. Used to keep track of configuration changes
     * between releases, in case changes/updates are needed.
     *
     * <p>It only needs to be incremented for configuration changes (not releases of the add-on).
     *
     * @see #CONFIG_VERSION_KEY
     * @see #updateConfigsImpl(int)
     */
    private static final int CURRENT_CONFIG_VERSION = 1;

    /**
     * The key for the version of the configurations.
     *
     * @see #CURRENT_CONFIG_VERSION
     */
    private static final String CONFIG_VERSION_KEY = "spider" + VERSION_ATTRIBUTE;

    /** The Constant SPIDER_MAX_DEPTH. */
    private static final String SPIDER_MAX_DEPTH = "spider.maxDepth";

    /** The Constant SPIDER_THREAD. */
    private static final String SPIDER_THREAD = "spider.thread";

    /** The Constant SPIDER_POST_FORM. */
    private static final String SPIDER_POST_FORM = "spider.postform";

    /** The Constant SPIDER_PROCESS_FORM. */
    private static final String SPIDER_PROCESS_FORM = "spider.processform";

    /** The Constant SPIDER_SKIP_URL. */
    private static final String SPIDER_SKIP_URL = "spider.skipurl";

    /** The Constant SPIDER_REQUEST_WAIT. */
    private static final String SPIDER_REQUEST_WAIT = "spider.requestwait";

    /** The Constant SPIDER_PARSE_COMMENTS. */
    private static final String SPIDER_PARSE_COMMENTS = "spider.parseComments";

    /** The Constant SPIDER_PARSE_ROBOTS_TXT. */
    private static final String SPIDER_PARSE_ROBOTS_TXT = "spider.parseRobotsTxt";

    /** The Constant SPIDER_PARSE_SITEMAP_XML. */
    private static final String SPIDER_PARSE_SITEMAP_XML = "spider.parseSitemapXml";

    /** The Constant SPIDER_PARSE_SVN_ENTRIES. */
    private static final String SPIDER_PARSE_SVN_ENTRIES = "spider.parseSVNentries";

    /** The Constant SPIDER_PARSE_GIT. */
    private static final String SPIDER_PARSE_GIT = "spider.parseGit";

    /** The Constant SPIDER_HANDLE_PARAMETERS. */
    private static final String SPIDER_HANDLE_PARAMETERS = "spider.handleParameters";

    /** The Constant SPIDER_HANDLE_ODATA_PARAMETERS. */
    private static final String SPIDER_HANDLE_ODATA_PARAMETERS = "spider.handleODataParameters";

    private static final String DOMAIN_ALWAYS_IN_SCOPE_KEY = "spider.domainsAlwaysInScope";
    private static final String ALL_DOMAINS_ALWAYS_IN_SCOPE_KEY =
            DOMAIN_ALWAYS_IN_SCOPE_KEY + ".domainAlwaysInScope";
    private static final String DOMAIN_ALWAYS_IN_SCOPE_VALUE_KEY = "name";
    private static final String DOMAIN_ALWAYS_IN_SCOPE_REGEX_KEY = "regex";
    private static final String DOMAIN_ALWAYS_IN_SCOPE_ENABLED_KEY = "enabled";
    private static final String CONFIRM_REMOVE_DOMAIN_ALWAYS_IN_SCOPE =
            "spider.confirmRemoveDomainAlwaysInScope";

    private static final String IRRELEVANT_PARAMETERS_KEY = "spider.irrelevantParameters";
    private static final String ALL_IRRELEVANT_PARAMETERS_KEY =
            IRRELEVANT_PARAMETERS_KEY + ".irrelevantParameter";
    private static final String IRRELEVANT_PARAMETER_VALUE_KEY = "name";
    private static final String IRRELEVANT_PARAMETER_REGEX_KEY = "regex";
    private static final String IRRELEVANT_PARAMETER_ENABLED_KEY = "enabled";
    private static final String CONFIRM_REMOVE_IRRELEVANT_PARAMETER =
            IRRELEVANT_PARAMETERS_KEY + ".confirmRemove";

    private static final String MAX_SCANS_IN_UI = "spider.maxScansInUI";

    private static final String SHOW_ADV_DIALOG = "spider.advDialog";
    private static final String MAX_DURATION = "spider.maxDuration";

    private static final String MAX_CHILDREN = "spider.maxChildren";

    /**
     * Configuration key to write/read the {@code sendRefererHeader} flag.
     *
     * @see #sendRefererHeader
     */
    private static final String SPIDER_SENDER_REFERER_HEADER = "spider.sendRefererHeader";

    /** Configuration key to write/read the {@link #acceptCookies} flag. */
    private static final String SPIDER_ACCEPT_COOKIES = "spider.acceptCookies";

    /** Configuration key to write/read the {@link #maxParseSizeBytes} flag. */
    private static final String SPIDER_MAX_PARSE_SIZE_BYTES = "spider.maxParseSizeBytes";

    /**
     * Default maximum size, in bytes, that a response might have to be parsed.
     *
     * @see #maxParseSizeBytes
     */
    private static final int DEFAULT_MAX_PARSE_SIZE_BYTES = 2621440; // 2.5 MiB

    private ExtensionHttpSessions extensionHttpSessions;

    /**
     * This option is used to define how the parameters are used when checking if an URI was already
     * visited.
     */
    public enum HandleParametersOption {
        /** The parameters are ignored completely. */
        IGNORE_COMPLETELY,
        /** Only the name of the parameter is used, but the value is ignored. */
        IGNORE_VALUE,
        /** Both the name and value of the parameter are used. */
        USE_ALL;

        public String getName() {
            switch (this) {
                case IGNORE_COMPLETELY:
                    return Constant.messages.getString(
                            "spider.options.value.handleparameters.ignoreAll");
                case IGNORE_VALUE:
                    return Constant.messages.getString(
                            "spider.options.value.handleparameters.ignoreValue");
                case USE_ALL:
                    return Constant.messages.getString(
                            "spider.options.value.handleparameters.useAll");
                default:
                    return null;
            }
        }
    }

    /** The max depth of the crawling. */
    private int maxDepth = 5;
    /** The thread count. */
    private int threadCount = 2;
    /** Whether comments should be parsed for URIs. */
    private boolean parseComments = true;
    /** Whether robots.txt file should be parsed for URIs. */
    private boolean parseRobotsTxt = true;
    /** Whether sitemap.xml file should be parsed for URIs. */
    private boolean parseSitemapXml = true;
    /** Whether SVN entries files should be parsed for URIs. */
    private boolean parseSVNentries;
    /** Whether Git files should be parsed for URIs. */
    private boolean parseGit;
    /** Whether the forms are processed and submitted at all. */
    private boolean processForm = true;
    /**
     * Whether the forms are submitted, if their method is HTTP POST. This option should not be used
     * if the forms are not processed at all (processForm).
     */
    private boolean postForm = true;
    /** The waiting time between new requests to server - safe from DDOS. */
    private int requestWait = 200;
    /** Which urls are skipped. */
    private String skipURL = "";
    /** The pattern for skip url. */
    private Pattern patternSkipURL;
    /** The user agent string, if different than the default one. */
    private String userAgent;
    /** The handle parameters visited. */
    private HandleParametersOption handleParametersVisited = HandleParametersOption.USE_ALL;
    /**
     * Defines if we take care of OData specific parameters during the visit in order to identify
     * known URL *
     */
    private boolean handleODataParametersVisited;
    /** The maximum duration in minutes that the spider is allowed to run for, 0 meaning no limit */
    private int maxDuration;

    /** The maximum number of child nodes (per node) that can be crawled, 0 means no limit. */
    private int maxChildren;

    private List<DomainAlwaysInScopeMatcher> domainsAlwaysInScope = new ArrayList<>(0);
    private List<DomainAlwaysInScopeMatcher> domainsAlwaysInScopeEnabled = new ArrayList<>(0);
    private boolean confirmRemoveDomainAlwaysInScope;
    private int maxScansInUI = 5;
    private boolean showAdvancedDialog; // TODO load/save

    /** The log. */
    private static final Logger log = LogManager.getLogger(SpiderParam.class);

    /**
     * Flag that indicates if the 'Referer' header should be sent while spidering.
     *
     * <p>Default value is {@code true}.
     *
     * @see #SPIDER_SENDER_REFERER_HEADER
     * @see #isSendRefererHeader()
     * @see #setSendRefererHeader(boolean)
     */
    private boolean sendRefererHeader = true;

    /**
     * Flag that indicates if a spider process should accept cookies.
     *
     * <p>Default value is {@code true}.
     *
     * @see #SPIDER_ACCEPT_COOKIES
     * @see #isAcceptCookies()
     * @see #setAcceptCookies(boolean)
     */
    private boolean acceptCookies = true;

    /**
     * The maximum size, in bytes, that a response might have to be parsed.
     *
     * <p>Default value is {@value #DEFAULT_MAX_PARSE_SIZE_BYTES} bytes.
     *
     * @see #SPIDER_MAX_PARSE_SIZE_BYTES
     * @see #getMaxParseSizeBytes()
     * @see #setMaxParseSizeBytes(int)
     */
    private int maxParseSizeBytes = DEFAULT_MAX_PARSE_SIZE_BYTES;

    private List<IrrelevantParameter> irrelevantParameters;
    private List<IrrelevantParameter> irrelevantParametersEnabled;
    private boolean confirmRemoveIrrelevantParameter;

    /** Instantiates a new spider param. */
    public SpiderParam() {}

    @Override
    protected int getCurrentVersion() {
        return CURRENT_CONFIG_VERSION;
    }

    @Override
    protected String getConfigVersionKey() {
        return CONFIG_VERSION_KEY;
    }

    @Override
    protected void parseImpl() {
        updateOptions();

        extensionHttpSessions =
                Control.getSingleton()
                        .getExtensionLoader()
                        .getExtension(ExtensionHttpSessions.class);

        this.threadCount = getInt(SPIDER_THREAD, 2);

        this.maxDepth = getInt(SPIDER_MAX_DEPTH, 5);

        this.maxDuration = getInt(MAX_DURATION, 0);

        this.maxChildren = getInt(MAX_CHILDREN, 0);

        this.maxScansInUI = getInt(MAX_SCANS_IN_UI, 5);

        this.showAdvancedDialog = getBoolean(SHOW_ADV_DIALOG, false);

        this.processForm = getBoolean(SPIDER_PROCESS_FORM, true);

        try {
            this.postForm = getConfig().getBoolean(SPIDER_POST_FORM, true);
        } catch (ConversionException e) {
            // conversion issue from 1.4.1: convert the field from int to boolean
            log.info(
                    "Warning while parsing config file: {} was not in the expected format due to an upgrade. Converting it!",
                    SPIDER_POST_FORM);
            this.postForm = !getConfig().getProperty(SPIDER_POST_FORM).toString().equals("0");
            getConfig().setProperty(SPIDER_POST_FORM, String.valueOf(postForm));
        }

        this.requestWait = getInt(SPIDER_REQUEST_WAIT, 200);

        this.parseComments = getBoolean(SPIDER_PARSE_COMMENTS, true);

        this.parseRobotsTxt = getBoolean(SPIDER_PARSE_ROBOTS_TXT, true);

        this.parseSitemapXml = getBoolean(SPIDER_PARSE_SITEMAP_XML, true);

        this.parseSVNentries = getBoolean(SPIDER_PARSE_SVN_ENTRIES, false);

        this.parseGit = getBoolean(SPIDER_PARSE_GIT, false);

        this.skipURL = getString(SPIDER_SKIP_URL, "");
        parseSkipURL(this.skipURL);

        handleParametersVisited =
                HandleParametersOption.valueOf(
                        getString(
                                SPIDER_HANDLE_PARAMETERS,
                                HandleParametersOption.USE_ALL.toString()));

        this.handleODataParametersVisited = getBoolean(SPIDER_HANDLE_ODATA_PARAMETERS, false);

        loadDomainsAlwaysInScope();
        this.confirmRemoveDomainAlwaysInScope =
                getBoolean(CONFIRM_REMOVE_DOMAIN_ALWAYS_IN_SCOPE, true);

        this.sendRefererHeader = getBoolean(SPIDER_SENDER_REFERER_HEADER, true);

        this.acceptCookies = getBoolean(SPIDER_ACCEPT_COOKIES, true);

        this.maxParseSizeBytes = getInt(SPIDER_MAX_PARSE_SIZE_BYTES, DEFAULT_MAX_PARSE_SIZE_BYTES);

        loadIrrelevantParameters();
        this.confirmRemoveIrrelevantParameter =
                getBoolean(CONFIRM_REMOVE_IRRELEVANT_PARAMETER, true);
    }

    @Override
    protected void updateConfigsImpl(int fileVersion) {
        switch (fileVersion) {
            case NO_CONFIG_VERSION:
                setIrrelevantParameters(
                        Collections.singletonList(
                                new IrrelevantParameter(Pattern.compile("utm_.*"))));
                break;
            default:
        }
    }

    private void updateOptions() {
        final String oldDomainsInScope = "spider.scope";
        if (getConfig().containsKey(oldDomainsInScope)) {
            migrateOldDomainsInScopeOption(getConfig().getString(oldDomainsInScope, ""));
            getConfig().clearProperty(oldDomainsInScope);
        }
    }

    private void migrateOldDomainsInScopeOption(String oldDomainsInScope) {
        List<DomainAlwaysInScopeMatcher> domainsInScope =
                convertOldDomainsInScopeOption(oldDomainsInScope);

        if (!domainsInScope.isEmpty()) {
            setDomainsAlwaysInScope(domainsInScope);
        }
    }

    private static List<DomainAlwaysInScopeMatcher> convertOldDomainsInScopeOption(
            String oldDomainsInScope) {
        if (oldDomainsInScope == null || oldDomainsInScope.isEmpty()) {
            return Collections.emptyList();
        }

        ArrayList<DomainAlwaysInScopeMatcher> domainsInScope = new ArrayList<>();
        String[] names = oldDomainsInScope.split(";");
        for (String name : names) {
            String domain = name.trim();
            if (!domain.isEmpty()) {
                if (domain.contains("*")) {
                    domain = domain.replace(".", "\\.").replace("+", "\\+").replace("*", ".*?");
                    try {
                        Pattern pattern = Pattern.compile(domain, Pattern.CASE_INSENSITIVE);
                        domainsInScope.add(new DomainAlwaysInScopeMatcher(pattern));
                    } catch (IllegalArgumentException e) {
                        log.error("Failed to migrate a domain always in scope, name: {}", name, e);
                    }
                } else {
                    domainsInScope.add(new DomainAlwaysInScopeMatcher(domain));
                }
            }
        }
        domainsInScope.trimToSize();
        return domainsInScope;
    }

    /**
     * Gets the maximum depth the spider can crawl.
     *
     * @return the maximum depth, or {@value #UNLIMITED_DEPTH} if unlimited.
     * @see #setMaxDepth(int)
     */
    public int getMaxDepth() {
        return maxDepth;
    }

    /**
     * Sets the maximum depth the spider can crawl.
     *
     * <p>Value {@value #UNLIMITED_DEPTH} for unlimited depth.
     *
     * @param maxDepth the new maximum depth.
     * @see #getMaxDepth()
     */
    public void setMaxDepth(int maxDepth) {
        this.maxDepth = maxDepth > UNLIMITED_DEPTH ? maxDepth : UNLIMITED_DEPTH;
        getConfig().setProperty(SPIDER_MAX_DEPTH, Integer.toString(this.maxDepth));
    }

    /**
     * Gets the thread count.
     *
     * @return Returns the thread count
     */
    public int getThreadCount() {
        return threadCount;
    }

    /**
     * Sets the thread count.
     *
     * @param thread The thread count to set.
     */
    public void setThreadCount(int thread) {
        this.threadCount = thread;
        getConfig().setProperty(SPIDER_THREAD, Integer.toString(this.threadCount));
    }

    /**
     * Checks if is the forms should be submitted with the HTTP POST method. This option should not
     * be used if the forms are not processed at all (processForm).
     *
     * @return true, if the forms should be posted.
     */
    public boolean isPostForm() {
        return postForm;
    }

    /**
     * Sets if the forms should be submitted with the HTTP POST method. This option should not be
     * used if the forms are not processed at all (processForm).
     *
     * @param postForm the new post form status
     */
    public void setPostForm(boolean postForm) {
        this.postForm = postForm;
        getConfig().setProperty(SPIDER_POST_FORM, Boolean.toString(postForm));
    }

    /**
     * Checks if the forms should be processed.
     *
     * @return true, if the forms should be processed
     */
    public boolean isProcessForm() {
        return processForm;
    }

    /**
     * Sets if the forms should be processed.
     *
     * @param processForm the new process form status
     */
    public void setProcessForm(boolean processForm) {
        this.processForm = processForm;
        getConfig().setProperty(SPIDER_PROCESS_FORM, Boolean.toString(processForm));
    }

    /**
     * Sets the skip url string. This string is being parsed into a pattern which is used to check
     * if a url should be skipped while crawling.
     *
     * @param skipURL the new skip url string
     */
    public void setSkipURLString(String skipURL) {
        this.skipURL = skipURL;
        getConfig().setProperty(SPIDER_SKIP_URL, this.skipURL);
        parseSkipURL(this.skipURL);
    }

    /**
     * Gets the skip url string.
     *
     * @return the skip url string
     */
    public String getSkipURLString() {
        return skipURL;
    }

    /**
     * Checks if is this url should be skipped.
     *
     * @param uri the uri
     * @return true, if the url should be skipped
     */
    public boolean isSkipURL(URI uri) {
        if (patternSkipURL == null || uri == null) {
            return false;
        }
        String sURI = uri.toString();
        return patternSkipURL.matcher(sURI).find();
    }

    /**
     * Parses the skip url string.
     *
     * @param skipURL the skip url string
     */
    private void parseSkipURL(String skipURL) {
        patternSkipURL = null;

        if (skipURL == null || skipURL.equals("")) {
            return;
        }

        skipURL = skipURL.replaceAll("\\.", "\\\\.");
        skipURL = skipURL.replaceAll("\\*", ".*?").replaceAll("(\\s+$)|(^\\s+)", "");
        skipURL = "\\A(" + skipURL.replaceAll("\\s+", "|") + ")";
        patternSkipURL = Pattern.compile(skipURL, Pattern.CASE_INSENSITIVE | Pattern.MULTILINE);
    }

    /**
     * Gets the time between the requests sent to a server.
     *
     * @return the request wait time
     */
    public int getRequestWaitTime() {
        return requestWait;
    }

    /**
     * Sets the time between the requests sent to a server.
     *
     * @param requestWait the new request wait time
     */
    public void setRequestWaitTime(int requestWait) {
        this.requestWait = requestWait;
        this.getConfig().setProperty(SPIDER_REQUEST_WAIT, Integer.toString(requestWait));
    }

    /**
     * Gets the user agent.
     *
     * @return the user agent
     */
    public String getUserAgent() {
        return userAgent;
    }

    /**
     * Sets the user agent, if different from the default one.
     *
     * @param userAgent the new user agent
     */
    public void setUserAgent(String userAgent) {
        this.userAgent = userAgent;
    }

    /**
     * Checks if the spider should parse the comments.
     *
     * @return true, if it parses the comments
     */
    public boolean isParseComments() {
        return parseComments;
    }

    /**
     * Sets the whether the spider parses the comments.
     *
     * @param parseComments the new parses the comments value
     */
    public void setParseComments(boolean parseComments) {
        this.parseComments = parseComments;
        getConfig().setProperty(SPIDER_PARSE_COMMENTS, Boolean.toString(parseComments));
    }

    /**
     * Checks if the spider should parse the robots.txt for uris (not related to following the
     * directions).
     *
     * @return true, if it parses the file
     */
    public boolean isParseRobotsTxt() {
        return parseRobotsTxt;
    }

    /**
     * Checks if the spider should parse the sitemap.xml for URIs.
     *
     * @return true, if it parses the file
     */
    public boolean isParseSitemapXml() {
        return parseSitemapXml;
    }

    /**
     * Checks if the spider should parse the SVN entries files for URIs (not related to following
     * the directions).
     *
     * @return true, if it parses the file
     */
    public boolean isParseSVNEntries() {
        return parseSVNentries;
    }

    /**
     * Checks if the spider should parse the Git files for URIs.
     *
     * @return true, if it parses the files
     */
    public boolean isParseGit() {
        return parseGit;
    }

    /**
     * Sets the whether the spider parses the robots.txt for uris (not related to following the
     * directions).
     *
     * @param parseRobotsTxt the new value for parseRobotsTxt
     */
    public void setParseRobotsTxt(boolean parseRobotsTxt) {
        this.parseRobotsTxt = parseRobotsTxt;
        getConfig().setProperty(SPIDER_PARSE_ROBOTS_TXT, Boolean.toString(parseRobotsTxt));
    }

    /**
     * Sets the whether the spider parses the sitemap.xml for URIs.
     *
     * @param parseSitemapXml the new value for parseSitemapXml
     */
    public void setParseSitemapXml(boolean parseSitemapXml) {
        this.parseSitemapXml = parseSitemapXml;
        getConfig().setProperty(SPIDER_PARSE_SITEMAP_XML, Boolean.toString(parseSitemapXml));
    }

    /**
     * Sets the whether the spider parses the SVN entries file for URIs (not related to following
     * the directions).
     *
     * @param parseSVNentries the new value for parseSVNentries
     */
    public void setParseSVNEntries(boolean parseSVNentries) {
        this.parseSVNentries = parseSVNentries;
        getConfig().setProperty(SPIDER_PARSE_SVN_ENTRIES, Boolean.toString(parseSVNentries));
    }

    /**
     * Sets the whether the spider parses Git files for URIs
     *
     * @param parseGit the new value for parseGit
     */
    public void setParseGit(boolean parseGit) {
        this.parseGit = parseGit;
        getConfig().setProperty(SPIDER_PARSE_GIT, Boolean.toString(parseGit));
    }

    /**
     * Gets how the spider handles parameters when checking URIs visited.
     *
     * @return the handle parameters visited
     */
    public HandleParametersOption getHandleParameters() {
        return handleParametersVisited;
    }

    /**
     * Sets the how the spider handles parameters when checking URIs visited.
     *
     * @param handleParametersVisited the new handle parameters visited value
     */
    public void setHandleParameters(HandleParametersOption handleParametersVisited) {
        this.handleParametersVisited = handleParametersVisited;
        getConfig().setProperty(SPIDER_HANDLE_PARAMETERS, handleParametersVisited.toString());
    }

    /**
     * Sets the how the spider handles parameters when checking URIs visited.
     *
     * <p>The provided parameter is, in this case, a String which is cast to the proper value.
     * Possible values are: {@code "USE_ALL"}, {@code "IGNORE_VALUE"}, {@code "IGNORE_COMPLETELY"}.
     *
     * @param handleParametersVisited the new handle parameters visited value
     * @throws IllegalArgumentException if the given parameter is not a value of {@code
     *     HandleParametersOption}.
     */
    public void setHandleParameters(String handleParametersVisited) {
        this.handleParametersVisited = HandleParametersOption.valueOf(handleParametersVisited);
        getConfig().setProperty(SPIDER_HANDLE_PARAMETERS, this.handleParametersVisited.toString());
    }

    /**
     * Check if the spider should take into account OData-specific parameters (i.e : resource
     * identifiers) in order to identify already visited URL
     *
     * @return true, for handling OData parameters
     */
    public boolean isHandleODataParametersVisited() {
        return handleODataParametersVisited;
    }

    /**
     * Defines if the spider should handle OData specific parameters (i.e : resource identifiers) To
     * identify already visited URL
     *
     * @param handleODataParametersVisited the new value for handleODataParametersVisited
     */
    public void setHandleODataParametersVisited(boolean handleODataParametersVisited) {
        this.handleODataParametersVisited = handleODataParametersVisited;
        getConfig()
                .setProperty(
                        SPIDER_HANDLE_ODATA_PARAMETERS,
                        Boolean.toString(handleODataParametersVisited));
    }

    /**
     * Returns the domains that will be always in scope.
     *
     * @return the domains that will be always in scope.
     * @see #getDomainsAlwaysInScopeEnabled()
     * @see #setDomainsAlwaysInScope(List)
     */
    @ZapApiIgnore
    public List<DomainAlwaysInScopeMatcher> getDomainsAlwaysInScope() {
        return domainsAlwaysInScope;
    }

    /**
     * Returns the, enabled, domains that will be always in scope.
     *
     * @return the enabled domains that will be always in scope.
     * @see #getDomainsAlwaysInScope()
     * @see #setDomainsAlwaysInScope(List)
     */
    @ZapApiIgnore
    public List<DomainAlwaysInScopeMatcher> getDomainsAlwaysInScopeEnabled() {
        return domainsAlwaysInScopeEnabled;
    }

    /**
     * Sets the domains that will be always in scope.
     *
     * @param domainsAlwaysInScope the domains that will be excluded.
     */
    public void setDomainsAlwaysInScope(List<DomainAlwaysInScopeMatcher> domainsAlwaysInScope) {
        if (domainsAlwaysInScope == null || domainsAlwaysInScope.isEmpty()) {
            ((HierarchicalConfiguration) getConfig()).clearTree(ALL_DOMAINS_ALWAYS_IN_SCOPE_KEY);

            this.domainsAlwaysInScope = Collections.emptyList();
            this.domainsAlwaysInScopeEnabled = Collections.emptyList();
            return;
        }

        this.domainsAlwaysInScope = new ArrayList<>(domainsAlwaysInScope);

        ((HierarchicalConfiguration) getConfig()).clearTree(ALL_DOMAINS_ALWAYS_IN_SCOPE_KEY);

        int size = domainsAlwaysInScope.size();
        ArrayList<DomainAlwaysInScopeMatcher> enabledExcludedDomains = new ArrayList<>(size);
        for (int i = 0; i < size; ++i) {
            String elementBaseKey = ALL_DOMAINS_ALWAYS_IN_SCOPE_KEY + "(" + i + ").";
            DomainAlwaysInScopeMatcher excludedDomain = domainsAlwaysInScope.get(i);

            getConfig()
                    .setProperty(
                            elementBaseKey + DOMAIN_ALWAYS_IN_SCOPE_VALUE_KEY,
                            excludedDomain.getValue());
            getConfig()
                    .setProperty(
                            elementBaseKey + DOMAIN_ALWAYS_IN_SCOPE_REGEX_KEY,
                            excludedDomain.isRegex());
            getConfig()
                    .setProperty(
                            elementBaseKey + DOMAIN_ALWAYS_IN_SCOPE_ENABLED_KEY,
                            excludedDomain.isEnabled());

            if (excludedDomain.isEnabled()) {
                enabledExcludedDomains.add(excludedDomain);
            }
        }

        enabledExcludedDomains.trimToSize();
        this.domainsAlwaysInScopeEnabled = enabledExcludedDomains;
    }

    private void loadDomainsAlwaysInScope() {
        List<HierarchicalConfiguration> fields =
                ((HierarchicalConfiguration) getConfig())
                        .configurationsAt(ALL_DOMAINS_ALWAYS_IN_SCOPE_KEY);
        this.domainsAlwaysInScope = new ArrayList<>(fields.size());
        ArrayList<DomainAlwaysInScopeMatcher> domainsInScopeEnabled =
                new ArrayList<>(fields.size());
        for (HierarchicalConfiguration sub : fields) {
            String value = sub.getString(DOMAIN_ALWAYS_IN_SCOPE_VALUE_KEY, "");
            if ("".equals(value)) {
                log.warn(
                        "Failed to read an spider domain in scope entry, required value is empty.");
            }

            DomainAlwaysInScopeMatcher excludedDomain = null;
            boolean regex = sub.getBoolean(DOMAIN_ALWAYS_IN_SCOPE_REGEX_KEY, false);
            if (regex) {
                try {
                    Pattern pattern = DomainAlwaysInScopeMatcher.createPattern(value);
                    excludedDomain = new DomainAlwaysInScopeMatcher(pattern);
                } catch (IllegalArgumentException e) {
                    log.error(
                            "Failed to read an spider domain in scope entry with regex: {}",
                            value,
                            e);
                }
            } else {
                excludedDomain = new DomainAlwaysInScopeMatcher(value);
            }

            if (excludedDomain != null) {
                excludedDomain.setEnabled(sub.getBoolean(DOMAIN_ALWAYS_IN_SCOPE_ENABLED_KEY, true));

                domainsAlwaysInScope.add(excludedDomain);

                if (excludedDomain.isEnabled()) {
                    domainsInScopeEnabled.add(excludedDomain);
                }
            }
        }

        domainsInScopeEnabled.trimToSize();
        this.domainsAlwaysInScopeEnabled = domainsInScopeEnabled;
    }

    /**
     * Tells whether or not the remotion of a "domain always in scope" needs confirmation.
     *
     * @return {@code true} if the remotion needs confirmation, {@code false} otherwise.
     */
    @ZapApiIgnore
    public boolean isConfirmRemoveDomainAlwaysInScope() {
        return this.confirmRemoveDomainAlwaysInScope;
    }

    /**
     * Sets whether or not the remotion of a "domain always in scope" needs confirmation.
     *
     * @param confirmRemove {@code true} if the remotion needs confirmation, {@code false}
     *     otherwise.
     */
    @ZapApiIgnore
    public void setConfirmRemoveDomainAlwaysInScope(boolean confirmRemove) {
        this.confirmRemoveDomainAlwaysInScope = confirmRemove;
        getConfig()
                .setProperty(
                        CONFIRM_REMOVE_DOMAIN_ALWAYS_IN_SCOPE, confirmRemoveDomainAlwaysInScope);
    }

    public int getMaxScansInUI() {
        return maxScansInUI;
    }

    public void setMaxScansInUI(int maxScansInUI) {
        this.maxScansInUI = maxScansInUI;
        getConfig().setProperty(MAX_SCANS_IN_UI, this.maxScansInUI);
    }

    public boolean isShowAdvancedDialog() {
        return showAdvancedDialog;
    }

    public void setShowAdvancedDialog(boolean showAdvancedDialog) {
        this.showAdvancedDialog = showAdvancedDialog;
        getConfig().setProperty(SHOW_ADV_DIALOG, this.showAdvancedDialog);
    }

    /**
     * Tells whether or not the "Referer" header should be sent in spider requests.
     *
     * @return {@code true} if the "Referer" header should be sent in spider requests, {@code false}
     *     otherwise
     */
    public boolean isSendRefererHeader() {
        return sendRefererHeader;
    }

    /**
     * Sets whether or not the "Referer" header should be sent in spider requests.
     *
     * @param send {@code true} if the "Referer" header should be sent in spider requests, {@code
     *     false} otherwise
     */
    public void setSendRefererHeader(boolean send) {
        if (send == sendRefererHeader) {
            return;
        }

        this.sendRefererHeader = send;
        getConfig().setProperty(SPIDER_SENDER_REFERER_HEADER, this.sendRefererHeader);
    }

    /**
     * Returns the maximum duration in minutes that the spider should run for. Zero means no limit.
     *
     * @return the maximum time, in minutes, that the spider should run
     */
    public int getMaxDuration() {
        return maxDuration;
    }

    /**
     * Sets the maximum duration in minutes that the spider should run for. Zero means no limit.
     *
     * @param maxDuration the maximum time, in minutes, that the spider should run
     */
    public void setMaxDuration(int maxDuration) {
        this.maxDuration = maxDuration;
        getConfig().setProperty(MAX_DURATION, maxDuration);
    }

    /**
     * Gets the maximum number of child nodes (per node) that can be crawled, 0 means no limit.
     *
     * @return the maximum number of child nodes that can be crawled.
     */
    public int getMaxChildren() {
        return maxChildren;
    }

    /**
     * Sets the maximum number of child nodes (per node) that can be crawled, 0 means no limit.
     *
     * @param maxChildren the maximum number of child nodes that can be crawled.
     */
    public void setMaxChildren(int maxChildren) {
        this.maxChildren = maxChildren;
        getConfig().setProperty(MAX_CHILDREN, maxChildren);
    }

    /**
     * Sets whether or not a spider process should accept cookies while spidering.
     *
     * <p>For example, this might control whether or not the Spider uses the same session throughout
     * a spidering process.
     *
     * <p><strong>Notes:</strong>
     *
     * <ul>
     *   <li>This option has low priority, the Spider will respect other (global) options related to
     *       the HTTP state. This option is ignored if, for example, a {@link
     *       org.zaproxy.zap.users.User User} was set or the option {@link
     *       org.parosproxy.paros.network.ConnectionParam#isHttpStateEnabled() Session Tracking
     *       (Cookie)} is enabled.
     *   <li>The cookies are not shared between spider processes, each process has its own cookie
     *       jar.
     * </ul>
     *
     * @param acceptCookies {@code true} if the spider should accept cookies, {@code false}
     *     otherwise.
     * @see #isAcceptCookies()
     */
    public void setAcceptCookies(boolean acceptCookies) {
        this.acceptCookies = acceptCookies;
        getConfig().setProperty(SPIDER_ACCEPT_COOKIES, acceptCookies);
    }

    /**
     * Tells whether or not a spider process should accept cookies while spidering.
     *
     * <p>For example, this might control whether or not the Spider uses the same session throughout
     * a spidering process.
     *
     * @return {@code true} if the spider should accept cookies, {@code false} otherwise.
     * @see #setAcceptCookies(boolean)
     */
    public boolean isAcceptCookies() {
        return acceptCookies;
    }

    /**
     * Sets the maximum size, in bytes, that a response might have to be parsed.
     *
     * <p>This allows the spider to skip big responses/files.
     *
     * @param maxParseSizeBytes the maximum size, in bytes, that a response might have to be parsed.
     * @see #getMaxParseSizeBytes()
     */
    public void setMaxParseSizeBytes(int maxParseSizeBytes) {
        this.maxParseSizeBytes = maxParseSizeBytes;
        getConfig().setProperty(SPIDER_MAX_PARSE_SIZE_BYTES, maxParseSizeBytes);
    }

    /**
     * Gets the maximum size, in bytes, that a response might have to be parsed.
     *
     * @return the maximum size, in bytes, that a response might have to be parsed.
     * @see #setMaxParseSizeBytes(int)
     */
    public int getMaxParseSizeBytes() {
        return maxParseSizeBytes;
    }

    public boolean isIrrelevantUrlParameter(String name) {
        return irrelevantParametersEnabled.stream().anyMatch(e -> e.test(name))
                || isSessionToken(name);
    }

    private boolean isSessionToken(String paramName) {
        if (extensionHttpSessions == null) {
            return false;
        }
        return extensionHttpSessions.isDefaultSessionToken(paramName);
    }

    @ZapApiIgnore
    public List<IrrelevantParameter> getIrrelevantParameters() {
        return irrelevantParameters;
    }

    public void setIrrelevantParameters(List<IrrelevantParameter> irrelevantParameters) {
        if (irrelevantParameters == null || irrelevantParameters.isEmpty()) {
            ((HierarchicalConfiguration) getConfig()).clearTree(ALL_IRRELEVANT_PARAMETERS_KEY);

            this.irrelevantParameters = Collections.emptyList();
            this.irrelevantParametersEnabled = Collections.emptyList();
            return;
        }

        this.irrelevantParameters = new ArrayList<>(irrelevantParameters);

        ((HierarchicalConfiguration) getConfig()).clearTree(ALL_IRRELEVANT_PARAMETERS_KEY);

        int size = irrelevantParameters.size();
        ArrayList<IrrelevantParameter> enabledParameters = new ArrayList<>(size);
        for (int i = 0; i < size; ++i) {
            String elementBaseKey = ALL_IRRELEVANT_PARAMETERS_KEY + "(" + i + ").";
            IrrelevantParameter parameter = irrelevantParameters.get(i);

            getConfig()
                    .setProperty(
                            elementBaseKey + IRRELEVANT_PARAMETER_VALUE_KEY, parameter.getValue());
            getConfig()
                    .setProperty(
                            elementBaseKey + IRRELEVANT_PARAMETER_REGEX_KEY, parameter.isRegex());
            getConfig()
                    .setProperty(
                            elementBaseKey + IRRELEVANT_PARAMETER_ENABLED_KEY,
                            parameter.isEnabled());

            if (parameter.isEnabled()) {
                enabledParameters.add(parameter);
            }
        }

        enabledParameters.trimToSize();
        this.irrelevantParametersEnabled = enabledParameters;
    }

    private void loadIrrelevantParameters() {
        List<HierarchicalConfiguration> fields =
                ((HierarchicalConfiguration) getConfig())
                        .configurationsAt(ALL_IRRELEVANT_PARAMETERS_KEY);
        this.irrelevantParameters = new ArrayList<>(fields.size());
        ArrayList<IrrelevantParameter> parametersEnabled = new ArrayList<>(fields.size());
        for (HierarchicalConfiguration sub : fields) {
            String value = sub.getString(IRRELEVANT_PARAMETER_VALUE_KEY, "");
            if ("".equals(value)) {
                log.warn("Failed to read an irrelevant parameter entry, required value is empty.");
            }

            IrrelevantParameter parameter = null;
            boolean regex = sub.getBoolean(IRRELEVANT_PARAMETER_REGEX_KEY, false);
            if (regex) {
                try {
                    Pattern pattern = IrrelevantParameter.createPattern(value);
                    parameter = new IrrelevantParameter(pattern);
                } catch (IllegalArgumentException e) {
                    log.error(
                            "Failed to read an irrelevant parameter entry with regex: {}",
                            value,
                            e);
                }
            } else {
                parameter = new IrrelevantParameter(value);
            }

            if (parameter != null) {
                parameter.setEnabled(sub.getBoolean(IRRELEVANT_PARAMETER_ENABLED_KEY, true));

                irrelevantParameters.add(parameter);

                if (parameter.isEnabled()) {
                    parametersEnabled.add(parameter);
                }
            }
        }

        parametersEnabled.trimToSize();
        this.irrelevantParametersEnabled = parametersEnabled;
    }

    @ZapApiIgnore
    public boolean isConfirmRemoveIrrelevantParameter() {
        return this.confirmRemoveIrrelevantParameter;
    }

    @ZapApiIgnore
    public void setConfirmRemoveIrrelevantParameter(boolean confirmRemove) {
        this.confirmRemoveIrrelevantParameter = confirmRemove;
        getConfig()
                .setProperty(CONFIRM_REMOVE_IRRELEVANT_PARAMETER, confirmRemoveIrrelevantParameter);
    }
}
