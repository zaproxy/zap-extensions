import org.zaproxy.gradle.addon.AddOnStatus

description = "Imports and spiders OpenAPI definitions."

zapAddOn {
    addOnName.set("OpenAPI Support")
    addOnStatus.set(AddOnStatus.BETA)
    zapVersion.set("2.11.1")

    manifest {
        author.set("ZAP Dev Team plus Joanna Bona, Nathalie Bouchahine, Artur Grzesica, Mohammad Kamar, Markus Kiss, Michal Materniak, Marcin Spiewak, and SDA SE Open Industry Solutions")
        url.set("https://www.zaproxy.org/docs/desktop/addons/openapi-support/")
        extensions {
            register("org.zaproxy.zap.extension.openapi.automation.ExtensionOpenApiAutomation") {
                classnames {
                    allowed.set(listOf("org.zaproxy.zap.extension.openapi.automation"))
                }
                dependencies {
                    addOns {
                        register("automation") {
                            version.set(">=0.12.0")
                        }
                    }
                }
            }
            register("org.zaproxy.zap.extension.openapi.spider.ExtensionOpenApiSpider") {
                classnames {
                    allowed.set(listOf("org.zaproxy.zap.extension.openapi.spider"))
                }
                dependencies {
                    addOns {
                        register("spider") {
                            version.set(">=0.1.0")
                        }
                    }
                }
            }
            register("org.zaproxy.zap.extension.openapi.formhandler.ExtensionOpenApiFormHandler") {
                classnames {
                    allowed.set(listOf("org.zaproxy.zap.extension.openapi.formhandler"))
                }
                dependencies {
                    addOns {
                        register("formhandler") {
                            version.set(">=6.0.0 & < 7.0.0")
                        }
                    }
                }
            }
        }
        dependencies {
            addOns {
                register("commonlib") {
                    version.set(">= 1.8.0 & < 2.0.0")
                }
            }
        }
    }

    apiClientGen {
        api.set("org.zaproxy.zap.extension.openapi.OpenApiAPI")
        messages.set(file("src/main/resources/org/zaproxy/zap/extension/openapi/resources/Messages.properties"))
    }
}

configurations {
    "implementation" {
        // Not needed:
        exclude(group = "com.google.code.findbugs", module = "jsr305")
        exclude(group = "org.slf4j", module = "slf4j-ext")
    }
}

dependencies {
    compileOnly(parent!!.childProjects.get("automation")!!)
    compileOnly(parent!!.childProjects.get("commonlib")!!)
    compileOnly(parent!!.childProjects.get("formhandler")!!)
    compileOnly(parent!!.childProjects.get("spider")!!)

    implementation("io.swagger.parser.v3:swagger-parser:2.0.28")
    implementation("io.swagger:swagger-compat-spec-parser:1.0.56") {
        // Not needed:
        exclude(group = "com.github.java-json-tools", module = "json-schema-validator")
        exclude(group = "org.apache.httpcomponents", module = "httpclient")
    }
    implementation("org.apache.logging.log4j:log4j-slf4j-impl:2.17.2") {
        // Provided by ZAP.
        exclude(group = "org.apache.logging.log4j")
    }

    testImplementation(parent!!.childProjects.get("commonlib")!!)
    testImplementation(parent!!.childProjects.get("commonlib")!!.sourceSets.test.get().output)
    testImplementation("org.apache.logging.log4j:log4j-core:2.17.2")
    testImplementation(parent!!.childProjects.get("automation")!!)
    testImplementation(parent!!.childProjects.get("formhandler")!!)
    testImplementation(parent!!.childProjects.get("spider")!!)
    testImplementation(project(":testutils"))
}
