package org.zaproxy.zap.extension.prodscan.aem.spider;

import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.zaproxy.zap.spider.filters.ParseFilter;

public class SirenApiParseFilter extends ParseFilter {

    @Override
    public FilterResult filtered(HttpMessage message) {
        HttpResponseHeader header = message.getResponseHeader();
        if (!(header.isJson() && false)) {
            return FilterResult.WANTED;
        }
        return FilterResult.NOT_FILTERED;
    }

}
