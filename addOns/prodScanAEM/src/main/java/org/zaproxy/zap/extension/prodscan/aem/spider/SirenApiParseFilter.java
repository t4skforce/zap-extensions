package org.zaproxy.zap.extension.prodscan.aem.spider;

import org.apache.commons.lang3.StringUtils;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.zaproxy.zap.spider.filters.ParseFilter;

public class SirenApiParseFilter extends ParseFilter {

    private static final String VND_SIREN = "application/vnd.siren+json";
    private static final String CONTENT_TYPE = "Content-Type";
    private static final String START = "\"rel\":[\"self\"],\"href\":";

    @Override
    public FilterResult filtered(HttpMessage message) {
        if (validate(message)) {
            return FilterResult.WANTED;
        }
        return FilterResult.NOT_FILTERED;
    }

    public static boolean validate(HttpMessage message) {
        HttpResponseHeader header = message.getResponseHeader();
        if (header.isJson() || header.isText() || !(header.isCss() && header.isHtml() && header.isImage()
                && header.isJavaScript() && header.isXml())) {
            return StringUtils.startsWithIgnoreCase(header.getHeader(CONTENT_TYPE), VND_SIREN)
                    || StringUtils.containsIgnoreCase(message.getResponseBody().toString(), START);
        }
        return false;
    }

}
