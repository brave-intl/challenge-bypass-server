select execute($$

insert into migrations (id, description) values ('0002', 'rust_crypto');

drop table issuers;

create table issuers (
  issuerType text not null primary key,
  signingKey text not null,
  maxTokens integer not null
);

$$) where not exists (select * from migrations where id = '0002');
delete from issuers;
