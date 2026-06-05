-- Rebuild users to make password_hash nullable (SQLite can't drop NOT NULL in
-- place) and add OIDC columns.
create table users_new (
    username      text primary key not null,
    password_hash text,
    role          text not null,
    projects      text not null,
    email         text,
    oidc_issuer   text,
    oidc_subject  text,
    auth          text not null default 'password'
);

insert into users_new (username, password_hash, role, projects)
    select username, password_hash, role, projects from users;

drop table users;
alter table users_new rename to users;

create unique index users_oidc_identity
    on users (oidc_issuer, oidc_subject)
    where oidc_issuer is not null;

-- Transient authorization-code flow state (state / nonce / PKCE verifier).
create table oidc_auth_state (
    state          text primary key not null,
    nonce          text not null,
    pkce_verifier  text not null,
    expires_at     timestamp not null
);
