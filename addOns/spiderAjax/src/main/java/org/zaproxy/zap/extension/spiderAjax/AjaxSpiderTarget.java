/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP Development Team
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
package org.zaproxy.zap.extension.spiderAjax;

import java.net.URI;
import org.apache.log4j.Logger;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.model.SessionStructure;
import org.zaproxy.zap.model.Target;
import org.zaproxy.zap.users.User;

/** A target of AJAX spider scans. */
public final class AjaxSpiderTarget {

    private static final Logger LOGGER = Logger.getLogger(AjaxSpiderTarget.class);

    private final URI startUri;
    private final boolean inScopeOnly;
    private final Context context;
    private final User user;
    private final AjaxSpiderParam options;
    private final boolean subtreeOnly;

    private AjaxSpiderTarget(
            URI startUri,
            boolean inScopeOnly,
            Context context,
            User user,
            AjaxSpiderParam options,
            boolean subtreeOnly) {
        this.startUri = startUri;
        this.inScopeOnly = inScopeOnly;
        this.context = context;
        this.user = user;
        this.options = options;
        this.subtreeOnly = subtreeOnly;
    }

    /**
     * Gets the start URI.
     *
     * @return the start URI, never {@code null}.
     */
    public URI getStartUri() {
        return startUri;
    }

    /**
     * Gets the {@code Context} that will be spidered.
     *
     * @return the context, or {@code null} if none.
     */
    public Context getContext() {
        return context;
    }

    /**
     * Gets the {@code User} that will be used.
     *
     * @return the user, or {@code null} if none.
     */
    public User getUser() {
        return user;
    }

    /**
     * Tells whether or not the spider should spider everything in scope.
     *
     * <p>Should be ignored if the target has a context.
     *
     * @return {@code true} if the spider should spider everything in scope, {@code false} otherwise
     */
    public boolean isInScopeOnly() {
        return inScopeOnly;
    }

    /**
     * Tells whether or not the spider should spider only a subtree.
     *
     * @return {@code true} to spider only a subtree, {@code false} otherwise.
     */
    public boolean isSubtreeOnly() {
        return subtreeOnly;
    }

    /**
     * Gets the options for spidering.
     *
     * @return the options, never {@code null}.
     */
    public AjaxSpiderParam getOptions() {
        return options;
    }

    public Target toTarget() {
        Target target = new Target();
        try {
            target.setStartNode(
                    SessionStructure.find(
                            Model.getSingleton(),
                            new org.apache.commons.httpclient.URI(
                                    this.getStartUri().toString(), false),
                            "GET",
                            ""));
        } catch (Exception e) {
            LOGGER.error("Failed to convert target URL " + this.getStartUri().toString(), e);
        }
        target.setContext(getContext());
        target.setInScopeOnly(this.isInScopeOnly());
        return target;
    }

    /**
     * Creates a new build of targets.
     *
     * @param session the current session
     * @return a new builder, never {@code null}.
     */
    public static Builder newBuilder(Session session) {
        return new Builder(session);
    }

    /** A builder of {@link AjaxSpiderTarget}. */
    public static final class Builder {

        private final Session session;
        private URI startUri;
        private boolean inScopeOnly;
        private Context context;
        private User user;
        private AjaxSpiderParam options;
        private boolean subtreeOnly;

        /**
         * Constructs a {@code Builder} with the given session
         *
         * @param session the current session
         * @throws IllegalArgumentException if the given parameter is {@code null}.
         */
        private Builder(Session session) {
            if (session == null) {
                throw new IllegalArgumentException("The parameter session must not be null.");
            }
            this.session = session;
        }

        /**
         * Sets the start URI.
         *
         * @param uri the start URI
         * @return this builder
         */
        public Builder setStartUri(URI uri) {
            this.startUri = uri;

            return this;
        }

        /**
         * Sets the context to spider.
         *
         * <p>Removes the user previously set, if any.
         *
         * @param context the context
         * @return this builder
         * @see #setUser(User)
         */
        public Builder setContext(Context context) {
            this.context = context;
            this.user = null;

            return this;
        }

        /**
         * Sets the user to spider as.
         *
         * <p>Overrides any context previously set.
         *
         * @param user the user
         * @return this builder
         * @see #setContext(Context)
         */
        public Builder setUser(User user) {
            this.user = user;
            this.context = user.getContext();

            return this;
        }

        /**
         * Sets the spidering options.
         *
         * @param options the options
         * @return this builder
         */
        public Builder setOptions(AjaxSpiderParam options) {
            this.options = options;

            return this;
        }

        /**
         * Sets whether or not the spider should spider everything in scope.
         *
         * @param inScopeOnly {@code true} to spider everything in scope, {@code false} otherwise.
         * @return this builder
         */
        public Builder setInScopeOnly(boolean inScopeOnly) {
            this.inScopeOnly = inScopeOnly;

            return this;
        }

        /**
         * Sets whether or not the spider should spider only a subtree.
         *
         * @param subtreeOnly {@code true} to spider only a subtree, {@code false} otherwise.
         * @return this builder
         */
        public Builder setSubtreeOnly(boolean subtreeOnly) {
            this.subtreeOnly = subtreeOnly;

            return this;
        }

        /**
         * Builds a new target using the configurations previously set.
         *
         * @return a new {@code AjaxSpiderTarget} with configurations previously set.
         * @throws IllegalStateException if any of the following conditions is true:
         *     <ul>
         *       <li>No starting URI specified;
         *       <li>No options specified;
         *       <li>If a context was specified and the starting URI does not belong to the context;
         *       <li>If spidering in scope only and the starting URI is not in scope.
         */
        public AjaxSpiderTarget build() {
            if (startUri == null) {
                throw new IllegalStateException("No starting URI specified.");
            }

            if (options == null) {
                throw new IllegalStateException("No options specified.");
            }

            if (context != null) {
                if (!context.isInContext(startUri.toString())) {
                    throw new IllegalStateException(
                            "The starting URI does not belong to the context.");
                }
            } else if (inScopeOnly && !session.isInScope(startUri.toString())) {
                throw new IllegalStateException("The starting URI is not in scope.");
            }

            return new AjaxSpiderTarget(startUri, inScopeOnly, context, user, options, subtreeOnly);
        }
    }
}
