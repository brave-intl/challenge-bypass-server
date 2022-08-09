ALTER TABLE issuers ADD COLUMN issuer_cohort smallint DEFAULT 1;

-- run manually
-- update issuers set issuer_type='51115c70-2f85-4620-b633-3c52b1912e5d:invalid' where id='2b96166a-7753-4b4c-89ac-0ce487ff111e';

