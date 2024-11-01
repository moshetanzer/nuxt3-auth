CREATE TABLE users (
    id character(15) NOT NULL,
    fname character varying(50) NOT NULL,
    lname character varying(50) NOT NULL,
    email character varying(100) NOT NULL,
    password text NOT NULL,
    role character varying(20) NOT NULL,
    failed_attempts integer DEFAULT 0 NOT NULL,
    email_verified boolean DEFAULT false NOT NULL,
    email_mfa boolean DEFAULT false NOT NULL,
    reset_token character varying(100),
    reset_token_expires_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY users
    ADD CONSTRAINT users_email_key UNIQUE (email);

ALTER TABLE ONLY users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


CREATE TABLE sessions (
    id character(64) NOT NULL,
    user_id character(15),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    last_activity_at TIMESTAMP DEFAULT NOW(),
    expires_at timestamp without time zone NOT NULL,
    two_factor_verified boolean DEFAULT false NOT NULL
);

ALTER TABLE ONLY sessions
    ADD CONSTRAINT sessions_pkey PRIMARY KEY (id);

CREATE INDEX idx_sessions_expires_at ON sessions USING btree (expires_at);

CREATE INDEX idx_sessions_user_id ON sessions USING btree (user_id);

ALTER TABLE ONLY sessions
    ADD CONSTRAINT sessions_user_id_fkey FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;

CREATE TABLE audit_logs (
    id serial NOT NULL,
    email character varying(100) NOT NULL,
    action character varying(100) NOT NULL,
    message text NOT NULL,
    ip character varying(50),
    user_agent text,
    status character varying(20) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);