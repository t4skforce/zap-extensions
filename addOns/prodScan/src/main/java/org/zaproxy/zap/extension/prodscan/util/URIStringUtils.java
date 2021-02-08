package org.zaproxy.zap.extension.prodscan.util;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Arrays;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.Optional;

import org.apache.commons.collections.MapUtils;
import org.apache.commons.httpclient.URI;
import org.apache.commons.lang.StringUtils;

public class URIStringUtils {
    public static final String UTF_8 = "UTF-8";

    public static Optional<String> setFileExtension(String url, String newExt) {
        int i = url.indexOf(URIUtils.FILE_EXTENSION_SEPARATOR, url.lastIndexOf(URIUtils.PATH_SEPARATOR));
        if (i != -1 && i != url.length() - 1) {
            String ext = StringUtils.substring(url, i + 1, url.length());
            if (!StringUtils.equalsIgnoreCase(ext, newExt)) {
                return Optional.of(StringUtils.substring(url, 0, i))
                        .map(p -> StringUtils.join(Arrays.asList(p, newExt), URIUtils.FILE_EXTENSION_SEPARATOR));
            }
        } else {
            return Optional.of(StringUtils.join(Arrays.asList(url, newExt), URIUtils.FILE_EXTENSION_SEPARATOR));
        }
        return Optional.empty();
    }

    public static Optional<String> prependFileExtension(String url, String extension) {
        int i = url.indexOf(URIUtils.FILE_EXTENSION_SEPARATOR, url.lastIndexOf(URIUtils.PATH_SEPARATOR));
        if (i != -1 && i != url.length() - 1) {
            String ext = StringUtils.substring(url, i + 1, url.length());
            if (!StringUtils.equalsIgnoreCase(ext, extension)) {
                return Optional.of(StringUtils.substring(url, 0, i))
                        .map(p -> StringUtils.join(Arrays.asList(p, extension, ext),
                                URIUtils.FILE_EXTENSION_SEPARATOR));
            }
        }
        return Optional.empty();
    }

    public static Optional<String> appendFileExtension(String url, String extension) {
        return appendWithSeparator(url, URIUtils.FILE_EXTENSION_SEPARATOR, extension);
    }

    public static Optional<String> appendWithSeparator(String url, String seperator, String postfix) {
        return URIUtils.parse(url)
                .map(origin -> URIUtils.appendWithSeparator(origin, seperator, postfix).orElse(null))
                .filter(Objects::nonNull)
                .map(URI::toString);
    }

    public static Optional<String> appendPath(String url, String postfix) {
        return appendWithSeparator(url, "/", postfix);
    }

    public static Optional<String> appendRaw(String url, String postfix) {
        return appendWithSeparator(url, StringUtils.EMPTY, postfix);
    }

    public static Optional<String> setPathSeparator(String url, String seperator) {
        return URIUtils.parse(url)
                .map(origin -> URIUtils.setPathSeparator(origin, seperator).orElse(null))
                .filter(Objects::nonNull)
                .map(URI::toString);
    }

    public static Optional<String> setQueryParams(String url, String query) {
        return URIUtils.parse(url)
                .map(origin -> URIUtils.setQueryParams(origin, query).orElse(null))
                .filter(Objects::nonNull)
                .map(URI::toString);
    }

    public static Optional<String> addQueryParam(String url, Map<String, String> params) {
        return URIUtils.parse(url)
                .map(origin -> URIUtils.addQueryParam(origin, params).orElse(null))
                .filter(Objects::nonNull)
                .map(URI::toString);
    }

    public static String getQueryParams(Map<String, String> params)
            throws UnsupportedOperationException, UnsupportedEncodingException {
        StringBuilder sb = new StringBuilder();
        if (MapUtils.isNotEmpty(params)) {
            for (Entry<String, String> param : params.entrySet()) {
                if (sb.length() > 0) {
                    sb.append(URIUtils.PARAM_SEPERATOR);
                }
                sb.append(String.format(URIUtils.KEY_VALUE_FORMAT, URLEncoder.encode(param.getKey().toString(), UTF_8),
                        URLEncoder.encode(param.getValue().toString(), UTF_8)));
            }
        }
        return sb.toString();
    }

}
