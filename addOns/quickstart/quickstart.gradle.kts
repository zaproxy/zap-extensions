import org.zaproxy.gradle.addon.AddOnStatus

description = "Provides a tab which allows you to quickly test a target application"

zapAddOn {
    addOnName.set("Quick Start")
    addOnStatus.set(AddOnStatus.RELEASE)
    zapVersion.set("2.11.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/quick-start/")

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
        dependencies {
            addOns {
                register("reports") {
                    version.set(">= 0.4.0")
                }
            }
        }
    }
}

repositories {
    maven {
        url = uri("https://oss.sonatype.org/content/repositories/snapshots/")
    }
}

dependencies {
    zap("org.zaproxy:zap:2.11.0-20210923.152813-2")

    compileOnly(parent!!.childProjects.get("reports")!!)
    compileOnly(parent!!.childProjects.get("selenium")!!)
    compileOnly(parent!!.childProjects.get("spiderAjax")!!)
}
