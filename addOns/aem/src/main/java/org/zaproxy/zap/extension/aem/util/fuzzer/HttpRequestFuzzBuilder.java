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
package org.zaproxy.zap.extension.aem.util.fuzzer;

import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.commons.httpclient.UsernamePasswordCredentials;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.log4j.Logger;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.aem.util.wrapper.HttpMessageWrapper;

public class HttpRequestFuzzBuilder {
    private static final Logger LOG = Logger.getLogger(HttpRequestFuzzBuilder.class);

    private Set<HttpMessageWrapper> msgs = new LinkedHashSet<>();

    private HttpRequestFuzzBuilder(HttpMessage originalMsg) {
        msgs.add(new HttpMessageWrapper(originalMsg).cloneRequest());
    }

    private HttpRequestFuzzBuilder(HttpMessageWrapper originalMsg) {
        msgs.add(originalMsg.cloneRequest());
    }

    public HttpRequestFuzzBuilder setFileExtension(String... extensions) {
        List<HttpMessageWrapper> newMessages = new ArrayList<>();
        for (HttpMessageWrapper msg : msgs) {
            newMessages.addAll(setFileExtension(msg, extensions));
        }
        msgs.addAll(newMessages);
        return this;
    }

    public HttpRequestFuzzBuilder prependFileExtension(String... prefixes) {
        List<HttpMessageWrapper> newMessages = new ArrayList<>();
        for (HttpMessageWrapper msg : msgs) {
            newMessages.addAll(prependFileExtension(msg, prefixes));
        }
        msgs.addAll(newMessages);
        return this;
    }

    public HttpRequestFuzzBuilder appendFileExtension(String... postfixes) {
        List<HttpMessageWrapper> newMessages = new ArrayList<>();
        for (HttpMessageWrapper msg : msgs) {
            newMessages.addAll(appendFileExtension(msg, postfixes));
        }
        msgs.addAll(newMessages);
        return this;
    }

    public HttpRequestFuzzBuilder appendPath(String... postfixes) {
        List<HttpMessageWrapper> newMessages = new ArrayList<>();
        for (HttpMessageWrapper msg : msgs) {
            newMessages.addAll(appendPath(msg, postfixes));
        }
        msgs.addAll(newMessages);
        return this;
    }

    public HttpRequestFuzzBuilder appendRaw(String... postfixes) {
        List<HttpMessageWrapper> newMessages = new ArrayList<>();
        for (HttpMessageWrapper msg : msgs) {
            newMessages.addAll(appendRaw(msg, postfixes));
        }
        msgs.addAll(newMessages);
        return this;
    }

    public HttpRequestFuzzBuilder appendRaw(Predicate<String> predicate, String... postfixes) {
        List<HttpMessageWrapper> newMessages = new ArrayList<>();
        for (HttpMessageWrapper msg : msgs) {
            try {
                if (predicate.test(msg.getRequestHeader().getURI().getPath())) {
                    newMessages.addAll(appendRaw(msg, postfixes));
                }
            } catch (URIException e) {
                LOG.error(e.getMessage(), e);
            }
        }
        msgs.addAll(newMessages);
        return this;
    }

    public HttpRequestFuzzBuilder appendWithSeparator(String separator, String... postfixes) {
        List<HttpMessageWrapper> newMessages = new ArrayList<>();
        for (HttpMessageWrapper msg : msgs) {
            newMessages.addAll(appendWithSeparator(msg, separator, postfixes));
        }
        msgs.addAll(newMessages);
        return this;
    }

    public HttpRequestFuzzBuilder setPathSeparator(String... separators) {
        List<HttpMessageWrapper> newMessages = new ArrayList<>();
        for (HttpMessageWrapper msg : msgs) {
            newMessages.addAll(setPathSeparator(msg, separators));
        }
        msgs.addAll(newMessages);
        return this;
    }

    public HttpRequestFuzzBuilder setQueryParam(String... queries) {
        List<HttpMessageWrapper> newMessages = new ArrayList<>();
        for (HttpMessageWrapper msg : msgs) {
            newMessages.addAll(setQueryParam(msg, queries));
        }
        msgs.addAll(newMessages);
        return this;
    }

    public HttpRequestFuzzBuilder authBasic(String... auths) {
        List<HttpMessageWrapper> newMessages = new ArrayList<>();
        for (HttpMessageWrapper msg : msgs) {
            newMessages.addAll(authBasic(msg, auths));
        }
        msgs.clear(); // we set the auth requests on all msgs
        msgs.addAll(newMessages);
        return this;
    }

    public HttpRequestFuzzBuilder join(HttpRequestFuzzBuilder builder) {
        msgs.addAll(builder.build());
        return this;
    }

    public static HttpRequestFuzzBuilder builder(HttpMessage originalMsg) {
        return new HttpRequestFuzzBuilder(originalMsg);
    }

    public List<HttpMessageWrapper> build() {
        return new ArrayList<>(msgs);
    }

    public Stream<HttpMessageWrapper> stream() {
        return msgs.stream();
    }

    /**
     * replace extension /test.html (json) -> /test.json
     *
     * @param originalMsg
     * @param extensions
     * @return
     */
    public static List<HttpMessageWrapper> setFileExtension(
            HttpMessageWrapper originalMsg, String... extensions) {
        if (Objects.isNull(originalMsg) || ArrayUtils.isEmpty(extensions)) {
            return Collections.emptyList();
        }
        URI origin = originalMsg.getRequestHeader().getURI();
        return Arrays.asList(extensions).stream()
                .filter(Objects::nonNull)
                .map(
                        extension -> {
                            HttpMessageWrapper msg = originalMsg.cloneRequest();
                            try {
                                Optional<String> newPath =
                                        setFileExtension(origin.getPath(), extension);
                                if (newPath.isPresent()) {
                                    msg.getRequestHeader()
                                            .setURI(
                                                    new URI(
                                                            origin.getScheme(),
                                                            origin.getAuthority(),
                                                            newPath.get(),
                                                            origin.getQuery(),
                                                            origin.getFragment()));
                                    return msg;
                                }
                            } catch (URIException e) {
                                LOG.error(e.getMessage(), e);
                            }
                            return null;
                        })
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
    }

    /**
     * prepend prefix to path /test.html (servlet) -> /test.servlet.html
     *
     * @param originalMsg
     * @param prefixes
     * @return
     */
    public static List<HttpMessageWrapper> prependFileExtension(
            HttpMessageWrapper originalMsg, String... prefixes) {
        if (Objects.isNull(originalMsg) || ArrayUtils.isEmpty(prefixes)) {
            return Collections.emptyList();
        }
        URI origin = originalMsg.getRequestHeader().getURI();
        return Arrays.asList(prefixes).stream()
                .filter(Objects::nonNull)
                .map(
                        prefix -> {
                            HttpMessageWrapper msg = originalMsg.cloneRequest();
                            try {
                                Optional<String> newPath =
                                        prependFileExtension(origin.getPath(), prefix);
                                if (newPath.isPresent()) {
                                    msg.getRequestHeader()
                                            .setURI(
                                                    new URI(
                                                            origin.getScheme(),
                                                            origin.getAuthority(),
                                                            newPath.get(),
                                                            origin.getQuery(),
                                                            origin.getFragment()));
                                    return msg;
                                }
                            } catch (URIException e) {
                                LOG.error(e.getMessage(), e);
                            }
                            return null;
                        })
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
    }

    /**
     * prepend prefix to path /test.html (servlet) -> /test.html.servlet
     *
     * @param originalMsg
     * @param postfixes
     * @return
     */
    public static List<HttpMessageWrapper> appendFileExtension(
            HttpMessageWrapper originalMsg, String... postfixes) {
        return appendWithSeparator(originalMsg, ".", postfixes);
    }

    /**
     * prepend prefix to path /test.html (servlet) -> /test.html/servlet
     *
     * @param originalMsg
     * @param postfixes
     * @return
     */
    public static List<HttpMessageWrapper> appendPath(
            HttpMessageWrapper originalMsg, String... postfixes) {
        return appendWithSeparator(originalMsg, "/", postfixes);
    }

    /**
     * prepend prefix to path /test.html (;servlet) -> /test.html;servlet
     *
     * @param originalMsg
     * @param postfixes
     * @return
     */
    public static List<HttpMessageWrapper> appendRaw(
            HttpMessageWrapper originalMsg, String... postfixes) {
        return appendWithSeparator(originalMsg, StringUtils.EMPTY, postfixes);
    }

    /**
     * prepend prefix to path /test.html (/,something) -> /test.html/something
     *
     * @param originalMsg
     * @param postfixes
     * @return
     */
    public static List<HttpMessageWrapper> appendWithSeparator(
            HttpMessageWrapper originalMsg, String separator, String... postfixes) {
        if (Objects.isNull(originalMsg) || Objects.isNull(separator)) {
            return Collections.emptyList();
        }
        URI origin = originalMsg.getRequestHeader().getURI();
        return Arrays.asList(postfixes).stream()
                .filter(Objects::nonNull)
                .map(
                        postfix -> {
                            HttpMessageWrapper msg = originalMsg.cloneRequest();
                            try {

                                msg.getRequestHeader()
                                        .setURI(
                                                new URI(
                                                        origin.getScheme(),
                                                        origin.getAuthority(),
                                                        StringUtils.join(
                                                                Arrays.asList(
                                                                        origin.getPath(), postfix),
                                                                separator),
                                                        origin.getQuery(),
                                                        origin.getFragment()));
                                return msg;

                            } catch (URIException e) {
                                LOG.error(e.getMessage(), e);
                            }
                            return null;
                        })
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
    }

    public static List<HttpMessageWrapper> setPathSeparator(
            HttpMessageWrapper originalMsg, String... separators) {
        if (Objects.isNull(originalMsg) || Objects.isNull(separators)) {
            return Collections.emptyList();
        }
        URI origin = originalMsg.getRequestHeader().getURI();
        return Arrays.asList(separators).stream()
                .filter(Objects::nonNull)
                .map(
                        separator -> {
                            HttpMessageWrapper msg = originalMsg.cloneRequest();
                            try {
                                String path =
                                        StringUtils.replaceEachRepeatedly(
                                                origin.getPath(),
                                                new String[] {"//"},
                                                new String[] {""});
                                if (StringUtils.contains(path, '/')) {
                                    msg.getRequestHeader()
                                            .setURI(
                                                    new URI(
                                                            origin.getScheme(),
                                                            origin.getAuthority(),
                                                            StringUtils.replace(
                                                                    path, "/", separator),
                                                            origin.getQuery(),
                                                            origin.getFragment()));
                                    return msg;
                                } else {
                                    msg.getRequestHeader()
                                            .setURI(
                                                    new URI(
                                                            origin.getScheme(),
                                                            origin.getAuthority(),
                                                            separator + path,
                                                            origin.getQuery(),
                                                            origin.getFragment()));
                                    return msg;
                                }
                            } catch (URIException e) {
                                LOG.error(e.getMessage(), e);
                            }
                            return null;
                        })
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
    }

    public static List<HttpMessageWrapper> setQueryParam(
            HttpMessageWrapper originalMsg, String... queries) {
        if (Objects.isNull(originalMsg) || Objects.isNull(queries)) {
            return Collections.emptyList();
        }
        URI origin = originalMsg.getRequestHeader().getURI();
        return Arrays.asList(queries).stream()
                .filter(Objects::nonNull)
                .map(
                        query -> {
                            HttpMessageWrapper msg = originalMsg.cloneRequest();
                            try {
                                msg.getRequestHeader()
                                        .setURI(
                                                new URI(
                                                        origin.getScheme(),
                                                        origin.getAuthority(),
                                                        origin.getPath(),
                                                        query,
                                                        origin.getFragment()));
                                return msg;
                            } catch (URIException e) {
                                LOG.error(e.getMessage(), e);
                            }
                            return null;
                        })
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
    }

    public static List<HttpMessageWrapper> authBasic(
            HttpMessageWrapper originalMsg, String... auths) {
        if (Objects.isNull(originalMsg) || Objects.isNull(auths)) {
            return Collections.emptyList();
        }
        return Arrays.asList(auths).stream()
                .filter(Objects::nonNull)
                .map(
                        auth -> {
                            HttpMessageWrapper msg = originalMsg.cloneRequest();
                            msg.getRequestHeader()
                                    .addHeader(
                                            "Authorization",
                                            MessageFormat.format(
                                                    "Basic {0}",
                                                    Base64.getEncoder()
                                                            .encodeToString(auth.getBytes())));
                            msg.getInfo()
                                    .put("authorization", new UsernamePasswordCredentials(auth));
                            return msg;
                        })
                .collect(Collectors.toList());
    }

    public static Optional<UsernamePasswordCredentials> getUserObject(HttpMessageWrapper msg) {
        return Optional.ofNullable(msg)
                .map(
                        ms -> {
                            Object obj = msg.getInfo().get("authorization");
                            if (obj instanceof UsernamePasswordCredentials) {
                                return (UsernamePasswordCredentials) obj;
                            }
                            return null;
                        })
                .filter(Objects::nonNull);
    }

    private static Optional<String> prependFileExtension(String path, String prefix) {
        int i = path.indexOf(".", path.lastIndexOf('/'));
        if (i != -1 && i != path.length() - 1) {
            String ext = StringUtils.substring(path, i + 1, path.length());
            if (!StringUtils.equalsIgnoreCase(ext, prefix)) {
                return Optional.of(StringUtils.substring(path, 0, i))
                        .map(p -> StringUtils.join(Arrays.asList(p, prefix, ext), '.'));
            }
        }
        return Optional.empty();
    }

    private static Optional<String> setFileExtension(String path, String newExt) {
        int i = path.indexOf(".", path.lastIndexOf('/'));
        if (i != -1 && i != path.length() - 1) {
            String ext = StringUtils.substring(path, i + 1, path.length());
            if (!StringUtils.equalsIgnoreCase(ext, newExt)) {
                return Optional.of(StringUtils.substring(path, 0, i))
                        .map(p -> StringUtils.join(Arrays.asList(p, newExt), '.'));
            }
        } else {
            return Optional.of(StringUtils.join(Arrays.asList(path, newExt), '.'));
        }
        return Optional.empty();
    }
}
