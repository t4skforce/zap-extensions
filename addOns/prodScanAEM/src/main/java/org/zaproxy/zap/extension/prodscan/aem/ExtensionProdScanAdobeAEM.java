package org.zaproxy.zap.extension.prodscan.aem;

import org.apache.log4j.Logger;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.zap.extension.prodscan.ExtensionProductScan;
import org.zaproxy.zap.extension.prodscan.aem.spider.SirenApiParseFilter;
import org.zaproxy.zap.extension.prodscan.aem.spider.SirenApiSpiderParser;
import org.zaproxy.zap.extension.spider.ExtensionSpider;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.spider.filters.ParseFilter;
import org.zaproxy.zap.spider.parser.SpiderParser;

public class ExtensionProdScanAdobeAEM extends ExtensionAdaptor {

    public static final String NAME = "ExtensionProdScanAdobeAEM";

    private static final Logger LOG = Logger.getLogger(ExtensionProdScanAdobeAEM.class);

    private ExtensionProductScan ps;

    private SpiderParser sirenApiSpiderParser;

    private ParseFilter sirenApiParseFilter;

    private Tech tech;

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        ps = (ExtensionProductScan) Control.getSingleton().getExtensionLoader().getExtension(ExtensionProductScan.NAME);

        if (ps != null) {
            tech = new Tech(ps.getRoot(), "AdobeAEM", "prodScanAEM.AdobeAEM");
            Tech.add(tech);
            LOG.debug("Added AdobeAEM Tech.");
        } else {
            LOG.debug("Could not add AdobeAEM Tech.");
        }

        ExtensionSpider spider = Control.getSingleton().getExtensionLoader().getExtension(ExtensionSpider.class);
        sirenApiSpiderParser = new SirenApiSpiderParser();
        sirenApiParseFilter = new SirenApiParseFilter();
        if (spider != null) {
            spider.addCustomParser(sirenApiSpiderParser);
            spider.addCustomParseFilter(sirenApiParseFilter);
            LOG.debug("Added AdobeAEM spider.");
        } else {
            LOG.debug("Could not add AdobeAEM spider.");
        }
    }

    @Override
    public void unload() {
        super.unload();
        Tech.remove(tech);

        ExtensionSpider spider = Control.getSingleton().getExtensionLoader().getExtension(ExtensionSpider.class);
        if (spider != null) {
            spider.removeCustomParser(sirenApiSpiderParser);
            spider.removeCustomParseFilter(sirenApiParseFilter);
            LOG.debug("Removed GraphQl spider.");
        }
    }

}
