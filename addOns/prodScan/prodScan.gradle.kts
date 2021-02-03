import org.zaproxy.gradle.addon.AddOnStatus

version = "1"
description = "Product Scanner"

zapAddOn {
    addOnName.set("Product Scanner")
    addOnStatus.set(AddOnStatus.ALPHA)
    zapVersion.set("2.9.0")

    manifest {
        author.set("Florian Neumair")
        url.set("")
        bundle {
            baseName.set("org.zaproxy.zap.extension.prodscan.resources.Messages")
            prefix.set("prodScan")
        }
    }
}

dependencies {
    // tests
    testImplementation(project(":testutils"))

    // compileOnly(parent!!.childProjects.get("selenium")!!)
    implementation("org.yaml:snakeyaml:1.26")
    // json query
    implementation("net.thisptr:jackson-jq:1.0.0-preview.20191208")
    // html query
    implementation("org.jdom:jdom:1.1.3")
    implementation("org.jsoup:jsoup:1.7.2")
    // reflections
    implementation("org.reflections:reflections:0.9.12")
    // commons collection
    implementation("org.apache.commons:commons-collections4:4.4")
}
