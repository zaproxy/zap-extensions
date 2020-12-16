import org.zaproxy.gradle.addon.AddOnStatus

version = "30"
description = "Provides a tab which allows you to quickly test a target application"

zapAddOn {
    addOnName.set("Quick Start")
    addOnStatus.set(AddOnStatus.RELEASE)
    zapVersion.set("2.9.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/quick-start/")
        notBeforeVersion.set("2.10.0")
        extensions {
            register("org.zaproxy.zap.extension.quickstart.ajaxspider.ExtensionQuickStartAjaxSpider") {
                classnames {
                    allowed.set(listOf("org.zaproxy.zap.extension.quickstart.ajaxspider"))
                }
                dependencies {
                    addOns {
                        register("selenium") {
                            version.set("15.*")
                        }
                        register("spiderAjax") {
                            version.set("23.*")
                        }
                    }
                }
            }
            register("org.zaproxy.zap.extension.quickstart.hud.ExtensionQuickStartHud") {
                classnames {
                    allowed.set(listOf("org.zaproxy.zap.extension.quickstart.hud"))
                }
                dependencies {
                    addOns {
                        register("hud") {
                            version.set(">= 0.4.0")
                        }
                    }
                }
            }
            register("org.zaproxy.zap.extension.quickstart.launch.ExtensionQuickStartLaunch") {
                classnames {
                    allowed.set(listOf("org.zaproxy.zap.extension.quickstart.launch"))
                }
                dependencies {
                    addOns {
                        register("selenium") {
                            version.set("15.*")
                        }
                    }
                }
            }
        }
    }
}

dependencies {
    compileOnly(parent!!.childProjects.get("selenium")!!)
    compileOnly(parent!!.childProjects.get("spiderAjax")!!)
}
