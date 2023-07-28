import org.zaproxy.gradle.addon.AddOnStatus

description = "Provides a tab which allows you to quickly test a target application"

zapAddOn {
    addOnName.set("Quick Start")
    addOnStatus.set(AddOnStatus.RELEASE)

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
                            version.set(">= 15.6.0")
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
            register("org.zaproxy.zap.extension.quickstart.spider.ExtensionQuickStartSpider") {
                classnames {
                    allowed.set(listOf("org.zaproxy.zap.extension.quickstart.spider"))
                }
                dependencies {
                    addOns {
                        register("spider") {
                            version.set(">=0.1.0")
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
                register("callhome") {
                    version.set(">= 0.0.1")
                }
                register("network") {
                    version.set(">= 0.3.0")
                }
            }
        }
    }
}

dependencies {
    zapAddOn("callhome")
    zapAddOn("network")
    zapAddOn("reports")
    zapAddOn("selenium")
    zapAddOn("spider")
    zapAddOn("spiderAjax")
}
