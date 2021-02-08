package org.zaproxy.zap.extension.prodscan.aem.spider;

import java.util.List;
import java.util.Optional;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.prodscan.util.JsonUtil;
import org.zaproxy.zap.spider.parser.SpiderParser;

import net.htmlparser.jericho.Source;

public class SirenApiSpiderParser extends SpiderParser {

    @Override
    public boolean parseResource(HttpMessage message, Source source, int depth) {
        String baseURL = message.getRequestHeader().getURI().toString();
        Optional<List<String>> findings = JsonUtil.strings(message, ".links[].href");
        findings.ifPresent(urls -> {
            urls.stream().forEach(url -> {
                processURL(message, depth, url, baseURL);
            });
        });
        return findings.isPresent();
    }

    @Override
    public boolean canParseResource(HttpMessage msg, String path, boolean wasAlreadyConsumed) {
        return SirenApiParseFilter.validate(msg);
    }

}
