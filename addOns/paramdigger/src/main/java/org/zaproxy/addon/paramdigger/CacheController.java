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
package org.zaproxy.addon.paramdigger;

import java.io.IOException;
import java.net.HttpCookie;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import org.apache.commons.httpclient.URI;
import org.apache.commons.lang.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpHeaderField;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.parosproxy.paros.network.HttpSender;

public class CacheController {

    private HttpSender httpSender;
    private HttpMessage base;
    private ParamDiggerConfig config;
    private Cache cache;
    private boolean cachingCheck;
    private HttpMessage bustedMessage;
    private SecureRandom random;
    private static final String METHOD_NOT_SUPPORTED = "paramdigger.method.not.supported";
    private static final int RANDOM_SEED = 1000;
    private final String[] headerList = {"Accept-Encoding", "Accept", "Cookie", "Origin"};
    private final String[] valueList = {"gzip, deflate, ", "*/*, text/", "paramdigger_cookie=", ""};
    private final String[] methodList = {"PURGE", "FASTLYPURGE"};

    private static final Logger logger = LogManager.getLogger(CacheController.class);

    public CacheController(HttpSender httpSender, ParamDiggerConfig config) {

        this.httpSender = httpSender;
        this.config = config;
        this.cache = new Cache();
        this.random = new SecureRandom();
    }

    /**
     * Checks if caching happens for a given URL.
     *
     * @param url the URL to check
     * @param method the method to use
     * @return a Cache object which holds the cache state of the site.
     */
    public void checkCaching(String url, Method method) {
        cachingCheck = true;
        /** Fetch default Headers of the site */
        HttpMessage msg = new HttpMessage();
        HttpRequestHeader headers = new HttpRequestHeader();
        switch (method) {
            case GET:
                headers.setMethod(HttpRequestHeader.GET);
                break;
            case POST:
                headers.setMethod(HttpRequestHeader.POST);
                break;
            default:
                break;
        }
        try {
            headers.setURI(new URI(url, true));
            headers.setVersion(HttpHeader.HTTP11);
            msg.setRequestHeader(headers);
            httpSender.sendAndReceive(msg);

            /* Set base response for comparison */
            this.base = msg;

            /* Analyze Response Headers */
            HttpResponseHeader responseHeader = this.base.getResponseHeader();
            List<HttpHeaderField> responseHeaders = responseHeader.getHeaders();
            for (HttpHeaderField header : responseHeaders) {
                String headerName = header.getName().toLowerCase();
                String headerValue = header.getValue();
                switch (headerName) {
                    case "cache-control":
                    case "pragma":
                        // TODO Add output to Output Panel with header value "%H Header was found
                        // with value %V"
                        break;
                    case "x-cache":
                    case "cf-cache-status":
                    case "x-drupal-cache":
                    case "x-varnish-cache":
                    case "akamai-cache-status":
                    case "server-timing":
                    case "x-iinfo":
                    case "x-nc":
                    case "x-hs-cf-cache-status":
                    case "x-proxy-cache":
                    case "x-cache-hits":
                        // TODO Add output to Output Panel with header value "%H Header was found
                        // with value %V"
                        cache.setIndicator(headerName);
                        break;

                    case "age":
                        /* This is set if Indicator in cache hasn't been set already */
                        // TODO Add output to Output Panel with header value "%H Header was found
                        // with value %V"
                        if (cache.getIndicator() == null || cache.getIndicator().isEmpty()) {
                            cache.setIndicator(headerName);
                        }
                        break;
                    default:
                        break;
                }
            }

            boolean alwaysMiss = false;
            if (cache.getIndicator() == null || cache.getIndicator().isEmpty()) {
                // TODO display some suitable message in OutputPanel that
                // since no x-cache (or other cache hit/miss header) header
                // was found the time will be measured as cache hit/miss indicator.
            } else {
                alwaysMiss = this.checkAlwaysMiss(url, method, cache);
            }
            /* If it's not an always miss, this means we can use a cachebuster */
            if (!alwaysMiss) {
                /* Check if a query parameter can be used a cache buster. */
                if (!cache.isCacheBusterFound()) {
                    config.setCacheBustingThreshold(-1);
                    this.cacheBusterParameter(url, method, cache);
                }

                /* Check if a header can be used as a cache buster. */
                if (!cache.isCacheBusterFound()) {
                    config.setCacheBustingThreshold(-1);
                    this.cacheBusterHeader(url, method, cache);
                }

                /* Check if a  cookie can be used as a cache buster. */
                if (!cache.isCacheBusterFound()) {
                    config.setCacheBustingThreshold(-1);
                    this.cacheBusterCookie(url, method, cache);
                }

                /* Check if a HTTP method can be used as a cache buster. */
                if (!cache.isCacheBusterFound()) {
                    config.setCacheBustingThreshold(-1);
                    this.cacheBusterHttpMethod(url, method, cache);
                }
            }
        } catch (Exception e) {
            // TODO Add error message display in output Panel
            logger.error(e, e);
        }
    }

    public boolean isCached(Method method) {
        if (!cachingCheck) {
            this.checkCaching(config.getUrl(), method);
        }
        if ((cache.getIndicator() != null || !cache.getIndicator().isEmpty())
                || cache.hasTimeIndicator()) {
            return cache.isCacheBusterFound();
        }
        return false;
    }

    public Cache getCache() {
        return cache;
    }

    /**
     * Checks if a HTTP Method can be used as a cache buster.
     *
     * @param url The URL to check.
     * @param method The HTTP Method to check.
     * @param cache The cache object to store the results in.
     * @throws IOException if request was not sent.
     * @throws IllegalArgumentException if the HTTP Method is not supported.
     */
    private void cacheBusterHttpMethod(String url, Method method, Cache cache)
            throws IOException, IllegalArgumentException {
        for (int i = 0; i < methodList.length; i++) {
            HttpRequestHeader headers = new HttpRequestHeader();
            headers.setURI(new URI(url, true));
            headers.setVersion(HttpHeader.HTTP11);
            if (cache.getIndicator() != null && !cache.getIndicator().isEmpty()) {
                /* We make use of the indicator */
                headers.setMethod(methodList[i]);
                HttpMessage msg = new HttpMessage();
                msg.setRequestHeader(headers);

                httpSender.sendAndReceive(msg);

                if (msg.getResponseHeader().getStatusCode()
                        == base.getResponseHeader().getStatusCode()) {
                    String indicValue = msg.getResponseHeader().getHeader(cache.getIndicator());
                    if (this.checkCacheHit(indicValue, cache)) {
                        // TODO show output that Method purging didn't work.
                    } else {
                        /* Now check If we have a hit to determine that the response is from cache. */
                        httpSender.sendAndReceive(msg);
                        if (msg.getResponseHeader().getStatusCode()
                                == base.getResponseHeader().getStatusCode()) {
                            indicValue = msg.getResponseHeader().getHeader(cache.getIndicator());
                            if (this.checkCacheHit(indicValue, cache)) {
                                cache.setCacheBusterFound(true);
                                cache.setCacheBusterIsHttpMethod(true);
                                cache.setCacheBusterName(methodList[i]);
                                this.bustedMessage = msg;
                            } else {
                                // TODO show output that Method purging didn't work.
                            }
                        }
                    }
                }
            } else {
                /* Since no indicator was found we try time difference. */
                /* Decide threshold */
                if (config.getCacheBustingThreshold() == -1) {
                    HttpRequestHeader headers2 = new HttpRequestHeader();
                    List<Integer> times = new ArrayList<Integer>();
                    for (int j = 0; j < 2; j++) {
                        headers2.setURI(new URI(url, true));
                        headers2.setVersion(HttpHeader.HTTP11);
                        if (j % 2 == 0) {
                            headers2.setMethod(methodList[i]);
                        } else {
                            switch (method) {
                                case GET:
                                    headers2.setMethod(HttpRequestHeader.GET);
                                    break;
                                case POST:
                                    headers2.setMethod(HttpRequestHeader.POST);
                                    break;
                                default:
                                    throw new IllegalArgumentException(
                                            Constant.messages.getString(
                                                    METHOD_NOT_SUPPORTED, method));
                            }
                        }
                        HttpMessage msg = new HttpMessage();
                        msg.setRequestHeader(headers2);
                        httpSender.sendAndReceive(msg);

                        if (msg.getResponseHeader().getStatusCode()
                                == base.getResponseHeader().getStatusCode()) {
                            times.add(msg.getTimeElapsedMillis());
                        }
                    }
                    if ((times.size() > 1)
                            && (times.get(0) > times.get(1))
                            && (times.get(0) - times.get(1)) >= 20) {
                        config.setCacheBustingThreshold(times.get(0) - times.get(1));
                    }
                }

                if (config.getCacheBustingThreshold() == -1) {
                    continue;
                }

                /* Try purging with calculated or given threshold. */
                List<Integer> times = new ArrayList<>();
                HttpMessage msg = new HttpMessage();
                for (int j = 0; j < 2; j++) {
                    if (j % 2 == 0) {
                        headers.setMethod(methodList[i]);
                    } else {
                        switch (method) {
                            case GET:
                                headers.setMethod(HttpRequestHeader.GET);
                                break;
                            case POST:
                                headers.setMethod(HttpRequestHeader.POST);
                                break;
                            default:
                                throw new IllegalArgumentException(
                                        Constant.messages.getString(METHOD_NOT_SUPPORTED, method));
                        }
                    }
                    msg.setRequestHeader(headers);

                    httpSender.sendAndReceive(msg);
                    times.add(msg.getTimeElapsedMillis());

                    if (msg.getResponseHeader().getStatusCode()
                            != base.getResponseHeader().getStatusCode()) {
                        // TODO show output that unexpected response code was received
                    }
                }

                boolean skip = false;
                for (int j = 1; j < times.size(); j += 2) {
                    if ((times.get(j - 1) - times.get(j) < config.getCacheBustingThreshold())) {
                        /* Since the response was faster then usual timing. We can assume it came from a cache. */
                        skip = true;
                        break;
                    }
                }
                if (skip) {
                    continue;
                }
                /* There is a cache and cache buster works! */
                cache.setTimeIndicator(true);
                cache.setCacheBusterFound(true);
                cache.setCacheBusterIsHttpMethod(true);
                cache.setCacheBusterName(methodList[i]);
                this.bustedMessage = msg;
            }
        }
    }

    /**
     * Checks if a cookie can be used as a cache buster. Requires users to specify what would be the
     * list of cookies that can be tried as cache busters.
     *
     * @param url The URL to check.
     * @param method The HTTP Method to check.
     * @param cache The cache object to store the results in.
     * @throws IOException if request was not sent.
     * @throws IllegalArgumentException if the HTTP Method is not supported.
     */
    private void cacheBusterCookie(String url, Method method, Cache cache)
            throws IOException, IllegalArgumentException {
        List<String> cookies = config.getCacheBustingCookies();
        for (int i = 0; i < cookies.size(); i++) {
            HttpRequestHeader headers = new HttpRequestHeader();
            headers.setURI(new URI(url, true));
            headers.setVersion(HttpHeader.HTTP11);
            switch (method) {
                case GET:
                    headers.setMethod(HttpRequestHeader.GET);
                    break;
                case POST:
                    headers.setMethod(HttpRequestHeader.POST);
                    break;
                default:
                    throw new IllegalArgumentException(
                            Constant.messages.getString(METHOD_NOT_SUPPORTED, method));
            }
            if (cache.getIndicator() != null && !cache.getIndicator().isEmpty()) {
                String cb = (Integer.valueOf(random.nextInt(RANDOM_SEED))).toString();
                HttpCookie cookie = new HttpCookie(cookies.get(i), cb);
                List<HttpCookie> cookieList = new ArrayList<>();
                cookieList.add(cookie);
                headers.setCookies(cookieList);

                HttpMessage msg = new HttpMessage();
                msg.setRequestHeader(headers);
                httpSender.sendAndReceive(msg);

                if (msg.getResponseHeader().getStatusCode()
                        == base.getResponseHeader().getStatusCode()) {
                    String indicValue = msg.getResponseHeader().getHeader(cache.getIndicator());
                    if (this.checkCacheHit(indicValue, cache)) {
                        // TODO show output that Cookie purging didn't work.
                    } else {
                        /* Now we try for a hit to determine the cachebuster works. */
                        httpSender.sendAndReceive(msg);
                        if (msg.getResponseHeader().getStatusCode()
                                == base.getResponseHeader().getStatusCode()) {
                            indicValue = msg.getResponseHeader().getHeader(cache.getIndicator());
                            if (this.checkCacheHit(indicValue, cache)) {
                                cache.setCacheBusterFound(true);
                                cache.setCacheBusterIsCookie(true);
                                cache.setCacheBusterName(cookies.get(i));
                                this.bustedMessage = msg;
                            } else {
                                // TODO show output that Cookie purging didn't work.
                            }
                        }
                    }
                }
            } else {
                /* time has to be considered. */
                /* First let's calculate the threshold. */
                if (config.getCacheBustingThreshold() == -1) {
                    HttpRequestHeader headers1 = new HttpRequestHeader();
                    headers1.setURI(new URI(url, true));
                    headers1.setVersion(HttpHeader.HTTP11);
                    headers1.setMethod(headers.getMethod());

                    List<Integer> times = new ArrayList<>();

                    for (int j = 0; j < 2; j++) {
                        if (j % 2 == 0) {
                            String cb = (Integer.valueOf(random.nextInt(RANDOM_SEED))).toString();
                            HttpCookie cookie = new HttpCookie(cookies.get(i), cb);
                            List<HttpCookie> cookieList = new ArrayList<>();
                            cookieList.add(cookie);
                            headers1.setCookies(cookieList);
                        }
                        HttpMessage msg1 = new HttpMessage();
                        msg1.setRequestHeader(headers1);
                        httpSender.sendAndReceive(msg1);

                        if (msg1.getResponseHeader().getStatusCode()
                                == base.getResponseHeader().getStatusCode()) {
                            times.add(msg1.getTimeElapsedMillis());
                        }
                    }
                    if ((times.size() > 1)
                            && (times.get(0) > times.get(1))
                            && (times.get(0) - times.get(1)) >= 20) {
                        config.setCacheBustingThreshold(20);
                    }
                }

                if (config.getCacheBustingThreshold() == -1) {
                    continue;
                }

                /* Try cookie busting with calculated or given threshold. */
                List<Integer> times = new ArrayList<>();
                HttpMessage msg = new HttpMessage();
                for (int j = 0; j < 4; j++) {
                    if (j % 2 == 0) {
                        String cb = (Integer.valueOf(random.nextInt(RANDOM_SEED))).toString();
                        HttpCookie cookie = new HttpCookie(cookies.get(i), cb);
                        List<HttpCookie> cookieList = new ArrayList<>();
                        cookieList.add(cookie);
                        headers.setCookies(cookieList);
                    }
                    msg.setRequestHeader(headers);
                    httpSender.sendAndReceive(msg);

                    times.add(msg.getTimeElapsedMillis());

                    if (msg.getResponseHeader().getStatusCode()
                            != base.getResponseHeader().getStatusCode()) {
                        // TODO show output that unexpected response code was received
                    }
                }

                boolean skip = false;

                for (int j = 1; j < times.size(); j += 2) {
                    if ((times.get(j - 1) - times.get(j) < config.getCacheBustingThreshold())) {
                        /* Since the response was faster then usual timing. We can assume it came from a cache. */
                        skip = true;
                        break;
                    }
                }
                if (skip) {
                    continue;
                }

                /* There is a cache and cache buster works! */
                cache.setTimeIndicator(true);
                cache.setCacheBusterFound(true);
                cache.setCacheBusterIsCookie(true);
                cache.setCacheBusterName(cookies.get(i));
                this.bustedMessage = msg;
            }
        }
    }

    /**
     * Checks if a HTTP header can be used as a cache buster.
     *
     * @param url The URL to check.
     * @param method The HTTP Method to check.
     * @param cache The cache object to store the results in.
     * @throws IOException if request was not sent.
     * @throws IllegalArgumentException if the HTTP Method is not supported.
     */
    private void cacheBusterHeader(String url, Method method, Cache cache)
            throws IOException, IllegalArgumentException {
        for (int i = 0; i < headerList.length; i++) {
            HttpRequestHeader headers = new HttpRequestHeader();
            HttpMessage msg = new HttpMessage();
            switch (method) {
                case GET:
                    headers.setMethod(HttpRequestHeader.GET);
                    break;
                case POST:
                    headers.setMethod(HttpRequestHeader.POST);
                    break;
                default:
                    throw new IllegalArgumentException(
                            Constant.messages.getString(METHOD_NOT_SUPPORTED, method));
            }
            headers.setURI(new URI(url, true));
            headers.setVersion(HttpHeader.HTTP11);

            /* If we have found an indicator then we use it. */
            if (cache.getIndicator() != null && !cache.getIndicator().isEmpty()) {
                String cacheBusterH = valueList[i] + random.nextInt(RANDOM_SEED);
                headers.addHeader(headerList[i], cacheBusterH);
                msg.setRequestHeader(headers);

                httpSender.sendAndReceive(msg);

                if (msg.getResponseHeader().getStatusCode()
                        == base.getResponseHeader().getStatusCode()) {
                    String indicValue = msg.getResponseHeader().getHeader(cache.getIndicator());
                    if (this.checkCacheHit(indicValue, cache)) {
                        // TODO show output that headr %H was tried as a cache buster but failed to
                        // work
                    } else {
                        /* Now we try for a hit to dtermine the cachebuster works and the response is from the cache. */
                        httpSender.sendAndReceive(msg);
                        if (msg.getResponseHeader().getStatusCode()
                                == base.getResponseHeader().getStatusCode()) {
                            indicValue = msg.getResponseHeader().getHeader(cache.getIndicator());
                            if (this.checkCacheHit(indicValue, cache)) {
                                cache.setCacheBusterFound(true);
                                cache.setCacheBusterIsHeader(true);
                                cache.setCacheBusterName(headerList[i]);
                                this.bustedMessage = msg;
                            } else {
                                // TODO show output that header %H was tried as a cache buster but
                                // failed to work
                            }
                        }
                    }
                }
            } else {
                /* Time is our friend */
                /* First we send two requests with a random cachebuster to determine
                the threshold value if we have opted in for default mode. */

                if (config.getCacheBustingThreshold() == -1) {
                    HttpRequestHeader headers2 = new HttpRequestHeader();
                    headers2.setMethod(headers.getMethod());
                    headers2.setURI(headers.getURI());
                    headers2.setVersion(headers.getVersion());
                    List<Integer> times = new ArrayList<>();
                    String randHead = "";
                    for (int j = 0; j < 2; j++) {
                        HttpMessage msg1 = new HttpMessage();
                        if (j % 2 == 0) {
                            randHead = valueList[i] + random.nextInt(RANDOM_SEED);
                        }
                        headers2.setHeader(headerList[i], randHead);
                        msg1.setRequestHeader(headers2);
                        httpSender.sendAndReceive(msg1);

                        if (msg1.getResponseHeader().getStatusCode()
                                == base.getResponseHeader().getStatusCode()) {
                            times.add(msg1.getTimeElapsedMillis());
                        }
                    }
                    if ((times.size() > 1)
                            && (times.get(0) > times.get(1))
                            && (times.get(0) - times.get(1)) >= 20) {
                        config.setCacheBustingThreshold(20);
                    }
                }

                if (config.getCacheBustingThreshold() == -1) {
                    continue;
                }

                List<Integer> timeList = new ArrayList<>();
                /* Setting it to a hardcoded value of 4 so as to reduce the time complexity. */
                String cacheBusterH = "";
                for (int j = 0; j < 4; j++) {
                    if (j % 2 == 0) {
                        cacheBusterH = valueList[i] + random.nextInt(RANDOM_SEED);
                    }
                    headers.setHeader(headerList[i], cacheBusterH);
                    msg.setRequestHeader(headers);

                    httpSender.sendAndReceive(msg);
                    timeList.add(msg.getTimeElapsedMillis());

                    if (msg.getResponseHeader().getStatusCode()
                            != base.getResponseHeader().getStatusCode()) {
                        // TODO show output that unexpected response code was received
                    }
                }

                boolean skip = false;
                for (int j = 1; j < timeList.size(); j += 2) {
                    if ((timeList.get(j - 1) - timeList.get(j)
                            < config.getCacheBustingThreshold())) {
                        /* Since the response was faster then usual timing. We can assume it came from a cache. */
                        skip = true;
                        break;
                    }
                }
                if (skip) {
                    continue;
                }
                /* There is a cache and cache buster works! */
                cache.setTimeIndicator(true);
                cache.setCacheBusterFound(true);
                cache.setCacheBusterIsHeader(true);
                cache.setCacheBusterName(headerList[i]);
                this.bustedMessage = msg;
            }
        }
    }

    /**
     * Generates a parameter string for a given URL.
     *
     * @param url The input URL to which the cachebuster has to be added
     * @return a URL with a cachebuster parameter having a random value.
     */
    private String generateParameterString(String url) {
        return this.createParameterString(
                url, config.getCacheBusterName(), "" + random.nextInt(RANDOM_SEED));
    }

    private String createParameterString(String url, String param, String value) {
        String newUrl;
        if (url.contains("?")) {
            newUrl = url + "&" + param + "=" + value;
        } else {
            newUrl = url + "?" + param + "=" + value;
        }
        return newUrl;
    }

    /**
     * Checks if a URL parameter can be used as a cache buster. If yes, then the cachebuster is
     * added to the cache object.
     *
     * @param url the URL to be checked.
     * @param method the HTTP method to be used (Refer to Method enum).
     * @param cache the Cache object storing the cache information about the site.
     * @throws IOException if request was not sent.
     * @throws IllegalArgumentException if the HTTP Method is not supported.
     */
    private void cacheBusterParameter(String url, Method method, Cache cache)
            throws IOException, IllegalArgumentException {
        String newUrl;
        HttpRequestHeader headers = new HttpRequestHeader();
        HttpMessage msg = new HttpMessage();
        switch (method) {
            case GET:
                headers.setMethod(HttpRequestHeader.GET);
                break;
            case POST:
                headers.setMethod(HttpRequestHeader.POST);
                break;
            default:
                throw new IllegalArgumentException(
                        Constant.messages.getString(METHOD_NOT_SUPPORTED, method));
        }

        /* If we have an indicator we use that to deteremine the presence of cache */
        if (cache.getIndicator() != null && !cache.getIndicator().isEmpty()) {
            newUrl = this.generateParameterString(url);
            headers.setURI(new URI(newUrl, true));
            headers.setVersion(HttpHeader.HTTP11);

            msg.setRequestHeader(headers);
            httpSender.sendAndReceive(msg);

            if (msg.getResponseHeader().getStatusCode()
                    == base.getResponseHeader().getStatusCode()) {
                String indicValue = msg.getResponseHeader().getHeader(cache.getIndicator());
                if (this.checkCacheHit(indicValue, cache)) {
                    // TODO show output that identifier defined in config.getCacheBusterName() was
                    // not successful
                } else {
                    /* Now we try to hit the cache to verify that the cachebuster works and the response is from the cache. */
                    httpSender.sendAndReceive(msg);
                    if (msg.getResponseHeader().getStatusCode()
                            == base.getResponseHeader().getStatusCode()) {
                        indicValue = msg.getResponseHeader().getHeader(cache.getIndicator());
                        if (this.checkCacheHit(indicValue, cache)) {
                            cache.setCacheBusterFound(true);
                            cache.setCacheBusterIsParameter(true);
                            cache.setCacheBusterName(config.getCacheBusterName());
                            this.bustedMessage = msg;
                        } else {
                            // TODO show output that identifier defined in
                            // config.getCacheBusterName()
                            // was not successful
                        }
                    }
                }
            }
        } else {
            /* This means we don't have any indicator and time is our only friend. */
            /* First we send two requests with a random cachebuster to determine
            the threshold value if we have opted in for default mode. */

            if (config.getCacheBustingThreshold() == -1) {
                HttpMessage msg1 = new HttpMessage();
                List<Integer> timeList = new ArrayList<>();
                String randomBuster = "zap";
                String randomBusterValue = "" + random.nextInt(RANDOM_SEED);
                for (int i = 0; i < 2; i++) {
                    newUrl = this.createParameterString(url, randomBuster, randomBusterValue);
                    headers.setURI(new URI(newUrl, true));
                    headers.setVersion(HttpHeader.HTTP11);

                    msg1.setRequestHeader(headers);
                    httpSender.sendAndReceive(msg1);

                    if (msg1.getResponseHeader().getStatusCode()
                            == base.getResponseHeader().getStatusCode()) {
                        timeList.add(msg1.getTimeElapsedMillis());
                    }
                }
                if ((timeList.size() > 1)
                        && (timeList.get(0) > timeList.get(1))
                        && (timeList.get(0) - timeList.get(1)) >= 20) {
                    config.setCacheBustingThreshold(20);
                }
            }

            if (config.getCacheBustingThreshold() == -1) {
                return;
            }

            List<Integer> times = new ArrayList<>();
            String old = "";
            for (int i = 0; i < config.getCacheBustingTimes(); i++) {
                if (i % 2 == 0) {
                    newUrl = this.generateParameterString(url);
                    old = newUrl;
                } else {
                    newUrl = old;
                }
                headers.setURI(new URI(newUrl, true));
                headers.setVersion(HttpHeader.HTTP11);

                msg.setRequestHeader(headers);
                httpSender.sendAndReceive(msg);

                times.add(msg.getTimeElapsedMillis());
                if (msg.getResponseHeader().getStatusCode()
                        != base.getResponseHeader().getStatusCode()) {
                    // TODO show unexpected status code error faced during time based cache busting
                }
            }

            boolean hits = false;
            for (int i = 1; i < times.size(); i += 2) {
                hits = true;
                if (times.get(i - 1) - times.get(i) < config.getCacheBustingThreshold()) {
                    return;
                }
            }
            if (hits) {
                cache.setTimeIndicator(true);
                cache.setCacheBusterFound(true);
                cache.setCacheBusterIsParameter(true);
                cache.setCacheBusterName(config.getCacheBusterName());
                this.bustedMessage = msg;
            }
        }
    }

    /**
     * Checks if every requests to the URL is a cache miss or not.
     *
     * @param url the URL to be checked.
     * @param method the HTTP method to be used (Refer to Method enum).
     * @param cache the Cache object storing the cache information about the site.
     * @return true if every request is a cache miss, false otherwise.
     */
    private boolean checkAlwaysMiss(String url, Method method, Cache cache) {
        HttpMessage msg = new HttpMessage();
        HttpRequestHeader requestHeader = new HttpRequestHeader();
        switch (method) {
            case GET:
                requestHeader.setMethod(HttpRequestHeader.GET);
                break;
            case POST:
                requestHeader.setMethod(HttpRequestHeader.POST);
                break;
            default:
                throw new IllegalArgumentException(
                        Constant.messages.getString(METHOD_NOT_SUPPORTED, method));
        }
        try {
            requestHeader.setURI(new URI(url, true));
            msg.setRequestHeader(requestHeader);
            httpSender.sendAndReceive(msg);
            if (msg.getResponseHeader().getStatusCode()
                    != base.getResponseHeader().getStatusCode()) {
                // TODO show error on output panel that unexpected status code match error was
                // faced.
            }
            String indicValue = msg.getResponseHeader().getHeader(cache.getIndicator());
            return (indicValue == null
                    || indicValue.isEmpty()
                    || !this.checkCacheHit(indicValue, cache));

        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Checks if there has been a cache hit or not using a given indicator value.
     *
     * @param indicValue the value of the indicator header.
     * @param cache the Cache object storing the cache information about the site.
     * @return true if there has been a cache hit, false otherwise.
     */
    private boolean checkCacheHit(String indicValue, Cache cache) {
        String indicator = cache.getIndicator();
        if (indicator.equalsIgnoreCase("age")) {
            indicValue = StringUtils.trim(indicValue);
            if (!indicValue.equals("0")) {
                return true;
            }
        }
        if (indicator.equalsIgnoreCase("x-iinfo")) {
            String[] values = StringUtils.split(indicValue, ',');
            if ((values.length > 1) && (values[1].contains("C") || values[1].contains("V"))) {
                return true;
            }
        }
        if (indicator.equalsIgnoreCase("x-cache-hits")) {
            for (String x : StringUtils.split(indicValue, ',')) {
                x = StringUtils.trim(x);
                if (!x.equals("0")) {
                    return true;
                }
            }
        }
        return indicValue.equalsIgnoreCase("hit");
    }

    public HttpMessage getBustedResponse() {
        return this.bustedMessage;
    }
}
