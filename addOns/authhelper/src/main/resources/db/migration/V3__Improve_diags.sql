
ALTER TABLE "AUTHHELPER_DIAGNOSTIC" ADD COLUMN "SCRIPT" VARCHAR(4194304) NULL;

ALTER TABLE "AUTHHELPER_DIAGNOSTIC_WEB_ELEMENT" ADD COLUMN "TAGNAME" VARCHAR(1024) NULL BEFORE "ATTRIBUTETYPE";

ALTER TABLE "AUTHHELPER_DIAGNOSTIC_MESSAGE" ADD COLUMN "INITIATOR" INTEGER DEFAULT 0 NOT NULL;


