select execute($$

insert into migrations (id, description) values ('0001', 'initial_schema');

create table issuers (
  issuerType text not null primary key,
  G text not null,
  H text not null,
  privateKey text not null,
  maxTokens integer not null
);


create table redemptions (
  id text not null primary key,
  issuerType text not null,
  ts timestamp not null,
  payload text
);

create index redemptions_type on redemptions using hash (issuerType);

$$) where not exists (select * from migrations where id = '0001');
