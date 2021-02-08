package org.zaproxy.zap.extension.prodscan.util;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.TreeMap;

import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.commons.lang.StringUtils;

public class URIUtils {

    public static final String PATH_SEPARATOR = "/";
    public static final String FILE_EXTENSION_SEPARATOR = ".";
    public static final String KEY_VALUE_SEPERATOR = "=";
    public static final String KEY_VALUE_FORMAT = "%s" + URIUtils.KEY_VALUE_SEPERATOR + "%s";
    public static final String PARAM_SEPERATOR = "&";

    public static Optional<URI> setFileExtension(URI origin, String newExt) {
        try {
            return URIStringUtils.setFileExtension(origin.getURI(), newExt).map(url -> {
                try {
                    return new URI(url, true);
                } catch (URIException e) {
                    // ignore
                } catch (NullPointerException e) {
                    // ignore
                }
                return null;
            }).filter(Objects::nonNull);
        } catch (URIException e) {
            return Optional.empty();
        }
    }

    public static Optional<URI> prependFileExtension(URI origin, String extension) {
        try {
            return URIStringUtils.prependFileExtension(origin.getURI(), extension).map(url -> {
                try {
                    return new URI(url, true);
                } catch (URIException e) {
                    // ignore
                } catch (NullPointerException e) {
                    // ignore
                }
                return null;
            }).filter(Objects::nonNull);
        } catch (URIException e) {
            return Optional.empty();
        }
    }

    public static Optional<URI> appendFileExtension(URI origin, String extension) {
        return appendWithSeparator(origin, FILE_EXTENSION_SEPARATOR, extension);
    }

    public static Optional<URI> appendWithSeparator(URI origin, String separator, String postfix) {
        try {
            return Optional.of(new URI(origin.getScheme(), origin.getAuthority(),
                    StringUtils.join(Arrays.asList(origin.getPath(), postfix), separator), origin.getQuery(),
                    origin.getFragment()));
        } catch (URIException e) {
            return Optional.empty();
        }
    }

    public static Optional<URI> appendPath(URI origin, String postfix) {
        return appendWithSeparator(origin, PATH_SEPARATOR, postfix);
    }

    public static Optional<URI> appendRaw(URI origin, String postfix) {
        return appendWithSeparator(origin, StringUtils.EMPTY, postfix);
    }

    public static Optional<URI> setPathSeparator(URI origin, String seperator) {
        try {
            String path = StringUtils.replaceEachRepeatedly(origin.getPath(),
                    new String[] { PATH_SEPARATOR + PATH_SEPARATOR }, new String[] { StringUtils.EMPTY });
            if (StringUtils.contains(path, PATH_SEPARATOR)) {
                return Optional.of(new URI(origin.getScheme(), origin.getAuthority(),
                        StringUtils.replace(path, PATH_SEPARATOR, seperator), origin.getQuery(), origin.getFragment()));
            } else {
                return Optional.of(new URI(origin.getScheme(), origin.getAuthority(), seperator + path,
                        origin.getQuery(), origin.getFragment()));
            }
        } catch (URIException e) {
            return Optional.empty();
        }
    }

    public static Optional<URI> setQueryParams(URI origin, String query) {
        try {
            return Optional.of(
                    new URI(origin.getScheme(), origin.getAuthority(), origin.getPath(), query, origin.getFragment()));
        } catch (URIException e) {
            return Optional.empty();
        }
    }

    public static Optional<URI> addQueryParam(URI origin, Map<String, String> params) {
        try {
            Map<String, String> originParams = getQueryParamsMap(origin);
            originParams.putAll(params);
            return setQueryParams(origin, URIStringUtils.getQueryParams(originParams));
        } catch (UnsupportedEncodingException e) {
            return Optional.empty();
        }
    }

    public static Map<String, String> getQueryParamsMap(URI url) {
        try {
            if (url == null) {
                return Collections.emptyMap();
            }

            // Get Query part of the url
            String queryPart = url.getQuery();
            if (queryPart == null || queryPart.isEmpty()) {
                return Collections.emptyMap();
            }

            Map<String, String> queryParams = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
            String[] pairs = queryPart.split(PARAM_SEPERATOR);
            for (String pair : pairs) {
                String[] keyValuePair = pair.split(KEY_VALUE_SEPERATOR);
                queryParams.put(URLDecoder.decode(keyValuePair[0], StandardCharsets.UTF_8.name()),
                        URLDecoder.decode(keyValuePair[1], StandardCharsets.UTF_8.name()));
            }
            return queryParams;
        } catch (URIException e) {
            // ignore
        } catch (UnsupportedEncodingException e) {
            // ignore
        }
        return Collections.emptyMap();
    }

    public static Optional<URI> parse(String url) {
        try {
            return Optional.of(new URI(url, false));
        } catch (URIException e) {
            // silent
        } catch (NullPointerException e) {
            // silent
        }
        return Optional.empty();
    }

}
