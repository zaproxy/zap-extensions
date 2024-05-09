import org.zaproxy.gradle.addon.AddOnStatus

description = "Imports and spiders OpenAPI definitions."

zapAddOn {
    addOnName.set("OpenAPI Support")
    addOnStatus.set(AddOnStatus.BETA)

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
                            version.set(">=0.31.0")
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
        }
        dependencies {
            addOns {
                register("commonlib") {
                    version.set(">= 1.26.0 & < 2.0.0")
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
    }
}

dependencies {
    zapAddOn("automation")
    zapAddOn("commonlib")
    zapAddOn("spider")

    implementation("io.swagger.parser.v3:swagger-parser:2.1.22") {
        // Provided by commonlib add-on:
        exclude(group = "com.fasterxml.jackson")
        exclude(group = "com.fasterxml.jackson.core")
        exclude(group = "com.fasterxml.jackson.dataformat")
        exclude(group = "com.fasterxml.jackson.datatype")
    }
    implementation("io.swagger:swagger-compat-spec-parser:1.0.70") {
        // Provided by commonlib add-on:
        exclude(group = "com.fasterxml.jackson")
        exclude(group = "com.fasterxml.jackson.core")
        exclude(group = "com.fasterxml.jackson.dataformat")
        exclude(group = "com.fasterxml.jackson.datatype")
        // Not needed:
        exclude(group = "com.github.java-json-tools", module = "json-schema-validator")
        exclude(group = "org.apache.httpcomponents", module = "httpclient")
    }
    implementation(libs.log4j.slf4j2) {
        // Provided by ZAP.
        exclude(group = "org.apache.logging.log4j")
    }

    testImplementation(parent!!.childProjects.get("commonlib")!!.sourceSets.test.get().output)
    testImplementation(libs.log4j.core)
    testImplementation(project(":testutils"))
}
