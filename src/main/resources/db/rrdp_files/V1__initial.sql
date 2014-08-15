CREATE TABLE rrdp_files (
    hash CHARACTER VARYING(2000) NOT NULL PRIMARY KEY,
    bytes CHARACTER VARYING NOT NULL,
    storage_time DATETIME NOT NULL
);

CREATE INDEX hash_idx ON rrdp_files(hash);