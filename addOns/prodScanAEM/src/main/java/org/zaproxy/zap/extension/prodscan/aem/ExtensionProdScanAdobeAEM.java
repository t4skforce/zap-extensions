package org.zaproxy.zap.extension.prodscan.aem;

import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.zap.extension.prodscan.ExtensionProductScan;
import org.zaproxy.zap.model.Tech;

public class ExtensionProdScanAdobeAEM extends ExtensionAdaptor {

    private ExtensionProductScan ps;

    private Tech tech;

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        ps = (ExtensionProductScan) Control.getSingleton().getExtensionLoader().getExtension(ExtensionProductScan.NAME);

        tech = new Tech(ps.getRoot(), "AdobeAEM", "prodScanAEM.AdobeAEM");
        Tech.add(tech);
    }

    @Override
    public void unload() {
        super.unload();
        Tech.remove(tech);
    }

}
