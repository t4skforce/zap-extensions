package org.zaproxy.zap.extension.prodscan;

import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.zaproxy.zap.model.Tech;

public class ExtensionProductScan extends ExtensionAdaptor {

    public static String NAME = "ExtensionProductScan";

    public Tech root;

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void init() {
        super.init();
        root = new Tech("Products", "prodscan.Products");
        Tech.add(root);
    }

    @Override
    public void unload() {
        super.unload();
        Tech.remove(root);
        root = null;
    }

    public Tech getRoot() {
        return root;
    }

}
