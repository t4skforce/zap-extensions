import org.zaproxy.gradle.addon.AddOnStatus

version = "1"
description = "Product Scanner"

zapAddOn {
    addOnName.set("Product Scanner")
    addOnStatus.set(AddOnStatus.ALPHA)
    zapVersion.set("2.10.0")

    manifest {
        author.set("Florian Neumair")
        url.set("")
        notBeforeVersion.set("2.10.0")
        extensions {
            register("org.zaproxy.zap.extension.prodscan.ExtensionProductScan")
        }
        bundle {
            baseName.set("org.zaproxy.zap.extension.prodscan.resources.Messages")
            prefix.set("prodscan")
        }
    }
}

dependencies {
    // tests
    testImplementation(project(":testutils"))

    // json query
    implementation("net.thisptr:jackson-jq:1.0.0-preview.20191208")
    // html query
    implementation("org.jdom:jdom:1.1.3")
    implementation("org.jsoup:jsoup:1.7.2")
    // commons collection
    implementation("org.apache.commons:commons-collections4:4.4")
}
