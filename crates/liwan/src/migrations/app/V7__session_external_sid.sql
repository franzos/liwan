-- The IdP's session id, so back-channel logout can end the one device the IdP
-- signed out rather than every session the account has. Null for password logins.
alter table sessions add column external_sid text;

create index sessions_external_sid on sessions (external_sid);
