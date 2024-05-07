import me.champeau.gradle.japicmp.JapicmpTask
import org.zaproxy.gradle.addon.AddOnStatus

description = "Spider used for automatically finding URIs on a site."

zapAddOn {
    addOnName.set("Spider")
    addOnStatus.set(AddOnStatus.RELEASE)

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/spider/")

        dependencies {
            addOns {
                register("database")
                register("network") {
                    version.set(">=0.3.0")
                }
                register("commonlib") {
                    version.set(">= 1.23.0 & < 2.0.0")
                }
            }
        }

        extensions {
            register("org.zaproxy.addon.spider.automation.ExtensionSpiderAutomation") {
                classnames {
                    allowed.set(listOf("org.zaproxy.addon.spider.automation"))
                }
                dependencies {
                    addOns {
                        register("automation") {
                            version.set(">=0.31.0")
                        }
                    }
                }
            }
        }
    }

    apiClientGen {
        api.set("org.zaproxy.addon.spider.SpiderAPI")
        options.set("org.zaproxy.addon.spider.SpiderParam")
    }
}

crowdin {
    configuration {
        val path = "org/zaproxy/addon/spider/resources/"
        tokens.put("%messagesPath%", path)
        tokens.put("%helpPath%", path)
    }
}

dependencies {
    zapAddOn("automation")
    zapAddOn("commonlib")
    zapAddOn("database")
    zapAddOn("network")

    implementation("io.kaitai:kaitai-struct-runtime:0.10")

    testImplementation(project(":testutils"))
}

val japicmp by tasks.existing(JapicmpTask::class) {
    packageExcludes = listOf("org.zaproxy.addon.spider.automation")
    methodExcludes = listOf("org.zaproxy.addon.spider.PopupMenuItemSpiderDialog#getParentMenuIndex()")
}

spotless {
    javaWith3rdPartyFormatted(
        project,
        listOf(
            "src/**/UrlCanonicalizer.java",
            "src/**/UrlResolver.java",
        ),
        listOf("src/**/DsStore.java"),
    )
}

tasks.named<Javadoc>("javadoc") {
    exclude("**/DsStore.java")
}
