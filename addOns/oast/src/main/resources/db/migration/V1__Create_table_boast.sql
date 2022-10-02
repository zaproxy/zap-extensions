create table BOAST (
    ID char(26) not null,
    CANARY char(26) not null,
    SECRET char(44) not null,
    URI varchar(512) not null,
    REGISTERED_TIMESTAMP timestamp not null
);
