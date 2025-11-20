--
-- PostgreSQL database dump
--

\restrict OGpOw5cgpr9CaXCX1DPnDB6QeuQjK3sdaQJNhweVYvbhLrinh6Bx199JHLPVEA5

-- Dumped from database version 15.15 (Debian 15.15-1.pgdg13+1)
-- Dumped by pg_dump version 15.15 (Debian 15.15-1.pgdg13+1)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: libinv; Type: SCHEMA; Schema: -; Owner: scancodeio
--

CREATE SCHEMA libinv;


ALTER SCHEMA libinv OWNER TO scancodeio;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: accounts; Type: TABLE; Schema: libinv; Owner: scancodeio
--

CREATE TABLE libinv.accounts (
    id character varying(12) NOT NULL,
    name character varying(50),
    type character varying(10) DEFAULT 'stage'::character varying NOT NULL
);


ALTER TABLE libinv.accounts OWNER TO scancodeio;

--
-- Name: actionable_package_available_versions; Type: TABLE; Schema: libinv; Owner: scancodeio
--

CREATE TABLE libinv.actionable_package_available_versions (
    uuid character varying(36) NOT NULL,
    scan_status character varying(20) NOT NULL,
    package_url character varying(300) NOT NULL,
    version character varying(100) NOT NULL,
    is_latest boolean NOT NULL,
    vulns_count integer,
    epss_score real,
    scan_output text,
    updated_at timestamp with time zone DEFAULT now(),
    is_version_in_use boolean,
    actionable_id character varying(36),
    scancode_project_uuid character varying(36)
);


ALTER TABLE libinv.actionable_package_available_versions OWNER TO scancodeio;

--
-- Name: deployment_checkpoints; Type: TABLE; Schema: libinv; Owner: scancodeio
--

CREATE TABLE libinv.deployment_checkpoints (
    id integer NOT NULL,
    active integer NOT NULL,
    checkpoint timestamp without time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


ALTER TABLE libinv.deployment_checkpoints OWNER TO scancodeio;

--
-- Name: deployment_checkpoints_id_seq; Type: SEQUENCE; Schema: libinv; Owner: scancodeio
--

CREATE SEQUENCE libinv.deployment_checkpoints_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE libinv.deployment_checkpoints_id_seq OWNER TO scancodeio;

--
-- Name: deployment_checkpoints_id_seq; Type: SEQUENCE OWNED BY; Schema: libinv; Owner: scancodeio
--

ALTER SEQUENCE libinv.deployment_checkpoints_id_seq OWNED BY libinv.deployment_checkpoints.id;


--
-- Name: epss; Type: TABLE; Schema: libinv; Owner: scancodeio
--

CREATE TABLE libinv.epss (
    cve character varying(50) NOT NULL,
    epss_score real NOT NULL,
    epss_percentile real NOT NULL,
    epss_date character varying(20),
    updated_at timestamp with time zone DEFAULT now()
);


ALTER TABLE libinv.epss OWNER TO scancodeio;

--
-- Name: image_package_association; Type: TABLE; Schema: libinv; Owner: scancodeio
--

CREATE TABLE libinv.image_package_association (
    image_id integer NOT NULL,
    package_id integer NOT NULL,
    metadata text
);


ALTER TABLE libinv.image_package_association OWNER TO scancodeio;

--
-- Name: images; Type: TABLE; Schema: libinv; Owner: scancodeio
--

CREATE TABLE libinv.images (
    id integer NOT NULL,
    name character varying(100) NOT NULL,
    backend_tech character varying(24),
    account_id character varying(12) NOT NULL,
    digest character varying(72) NOT NULL,
    tag character varying(128),
    commit character varying(128),
    platform character varying(24) NOT NULL,
    parent_image_id integer,
    base_image_id integer,
    repository_id integer,
    wasp_id integer,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


ALTER TABLE libinv.images OWNER TO scancodeio;

--
-- Name: images_id_seq; Type: SEQUENCE; Schema: libinv; Owner: scancodeio
--

CREATE SEQUENCE libinv.images_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE libinv.images_id_seq OWNER TO scancodeio;

--
-- Name: images_id_seq; Type: SEQUENCE OWNED BY; Schema: libinv; Owner: scancodeio
--

ALTER SEQUENCE libinv.images_id_seq OWNED BY libinv.images.id;


--
-- Name: latest_images; Type: TABLE; Schema: libinv; Owner: scancodeio
--

CREATE TABLE libinv.latest_images (
    image_id integer NOT NULL,
    account_id character varying(12) NOT NULL
);


ALTER TABLE libinv.latest_images OWNER TO scancodeio;

--
-- Name: layers; Type: TABLE; Schema: libinv; Owner: scancodeio
--

CREATE TABLE libinv.layers (
    id character(64) NOT NULL,
    image_id integer NOT NULL,
    seq integer NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


ALTER TABLE libinv.layers OWNER TO scancodeio;

--
-- Name: license_family; Type: TABLE; Schema: libinv; Owner: scancodeio
--

CREATE TABLE libinv.license_family (
    id integer NOT NULL,
    name character varying(150)
);


ALTER TABLE libinv.license_family OWNER TO scancodeio;

--
-- Name: license_family_id_seq; Type: SEQUENCE; Schema: libinv; Owner: scancodeio
--

CREATE SEQUENCE libinv.license_family_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE libinv.license_family_id_seq OWNER TO scancodeio;

--
-- Name: license_family_id_seq; Type: SEQUENCE OWNED BY; Schema: libinv; Owner: scancodeio
--

ALTER SEQUENCE libinv.license_family_id_seq OWNED BY libinv.license_family.id;


--
-- Name: package_license_association; Type: TABLE; Schema: libinv; Owner: scancodeio
--

CREATE TABLE libinv.package_license_association (
    package_id integer NOT NULL,
    license_id integer NOT NULL
);


ALTER TABLE libinv.package_license_association OWNER TO scancodeio;

--
-- Name: packages; Type: TABLE; Schema: libinv; Owner: scancodeio
--

CREATE TABLE libinv.packages (
    id integer NOT NULL,
    name character varying(100) NOT NULL,
    version character varying(150),
    language character varying(20),
    purl character varying(300),
    created_at timestamp without time zone DEFAULT now(),
    updated_at timestamp without time zone DEFAULT now()
);


ALTER TABLE libinv.packages OWNER TO scancodeio;

--
-- Name: packages_id_seq; Type: SEQUENCE; Schema: libinv; Owner: scancodeio
--

CREATE SEQUENCE libinv.packages_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE libinv.packages_id_seq OWNER TO scancodeio;

--
-- Name: packages_id_seq; Type: SEQUENCE OWNED BY; Schema: libinv; Owner: scancodeio
--

ALTER SEQUENCE libinv.packages_id_seq OWNED BY libinv.packages.id;


--
-- Name: repositories; Type: TABLE; Schema: libinv; Owner: scancodeio
--

CREATE TABLE libinv.repositories (
    id integer NOT NULL,
    provider character varying(200) NOT NULL,
    org character varying(200) NOT NULL,
    name character varying(200) NOT NULL,
    is_public boolean NOT NULL,
    pod character varying(200),
    subpod character varying(200)
);


ALTER TABLE libinv.repositories OWNER TO scancodeio;

--
-- Name: repositories_id_seq; Type: SEQUENCE; Schema: libinv; Owner: scancodeio
--

CREATE SEQUENCE libinv.repositories_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE libinv.repositories_id_seq OWNER TO scancodeio;

--
-- Name: repositories_id_seq; Type: SEQUENCE OWNED BY; Schema: libinv; Owner: scancodeio
--

ALTER SEQUENCE libinv.repositories_id_seq OWNED BY libinv.repositories.id;


--
-- Name: repository_actionable_package_versions_association; Type: TABLE; Schema: libinv; Owner: scancodeio
--

CREATE TABLE libinv.repository_actionable_package_versions_association (
    uuid character varying(36) NOT NULL,
    wasp_uuid character varying(36),
    actionable_package_version_id character varying(36),
    repository_id integer,
    environment character varying(20) NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


ALTER TABLE libinv.repository_actionable_package_versions_association OWNER TO scancodeio;

--
-- Name: safe_actionable; Type: TABLE; Schema: libinv; Owner: scancodeio
--

CREATE TABLE libinv.safe_actionable (
    uuid character varying(36) NOT NULL,
    package_url character varying(300) NOT NULL,
    updated_at timestamp with time zone DEFAULT now()
);


ALTER TABLE libinv.safe_actionable OWNER TO scancodeio;

--
-- Name: sast_lob_metadata; Type: TABLE; Schema: libinv; Owner: scancodeio
--

CREATE TABLE libinv.sast_lob_metadata (
    id integer NOT NULL,
    module character varying(1024) NOT NULL,
    sub_module character varying(1024) NOT NULL,
    repository_id integer,
    bugcounts integer,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


ALTER TABLE libinv.sast_lob_metadata OWNER TO scancodeio;

--
-- Name: sast_lob_metadata_id_seq; Type: SEQUENCE; Schema: libinv; Owner: scancodeio
--

CREATE SEQUENCE libinv.sast_lob_metadata_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE libinv.sast_lob_metadata_id_seq OWNER TO scancodeio;

--
-- Name: sast_lob_metadata_id_seq; Type: SEQUENCE OWNED BY; Schema: libinv; Owner: scancodeio
--

ALTER SEQUENCE libinv.sast_lob_metadata_id_seq OWNED BY libinv.sast_lob_metadata.id;


--
-- Name: sast_result; Type: TABLE; Schema: libinv; Owner: scancodeio
--

CREATE TABLE libinv.sast_result (
    id character varying(150) NOT NULL,
    lob_id integer,
    extras json,
    vulnsnippet text,
    githubpath character varying(1024),
    secbugurl character varying(1024),
    file_path character varying(1024),
    priority character varying(20),
    confidence character varying(20),
    description text,
    public_initial_point text,
    source character varying(200),
    isactive boolean,
    wasp_id integer,
    fixed_date timestamp without time zone,
    validated integer,
    validate_date timestamp without time zone,
    secbug_created_date timestamp without time zone,
    mean_solve_time integer,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


ALTER TABLE libinv.sast_result OWNER TO scancodeio;

--
-- Name: secbugs; Type: TABLE; Schema: libinv; Owner: scancodeio
--

CREATE TABLE libinv.secbugs (
    id character varying(50) NOT NULL,
    environment character varying(20),
    severity character varying(10),
    summary character varying(200),
    description character varying(500),
    vulnerability_category character varying(120),
    identified_by character varying(40),
    company character varying(20),
    is_risk boolean,
    pulled_at timestamp with time zone NOT NULL,
    deleted_at timestamp with time zone,
    repository_id integer,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


ALTER TABLE libinv.secbugs OWNER TO scancodeio;

--
-- Name: vulnerabilities; Type: TABLE; Schema: libinv; Owner: scancodeio
--

CREATE TABLE libinv.vulnerabilities (
    id character varying(50) NOT NULL,
    description character varying(500),
    severity character varying(10),
    related character varying(200),
    "nvd-cvss.base_score" real,
    "nvd-cvss.exploitability_score" real,
    "nvd-cvss.impact_score" real
);


ALTER TABLE libinv.vulnerabilities OWNER TO scancodeio;

--
-- Name: vulnerability_package_association; Type: TABLE; Schema: libinv; Owner: scancodeio
--

CREATE TABLE libinv.vulnerability_package_association (
    vulnerability_id character varying(50) NOT NULL,
    package_id integer NOT NULL,
    fix character varying(100)
);


ALTER TABLE libinv.vulnerability_package_association OWNER TO scancodeio;

--
-- Name: wasps; Type: TABLE; Schema: libinv; Owner: scancodeio
--

CREATE TABLE libinv.wasps (
    id integer NOT NULL,
    uuid character varying(36) NOT NULL,
    repository_id integer,
    tag character varying(128),
    commit character varying(128),
    environment character varying(128),
    jenkins_url character varying(256),
    raw_message character varying(2048) NOT NULL,
    ate_successfully boolean DEFAULT true NOT NULL,
    complaints text,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


ALTER TABLE libinv.wasps OWNER TO scancodeio;

--
-- Name: wasps_id_seq; Type: SEQUENCE; Schema: libinv; Owner: scancodeio
--

CREATE SEQUENCE libinv.wasps_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE libinv.wasps_id_seq OWNER TO scancodeio;

--
-- Name: wasps_id_seq; Type: SEQUENCE OWNED BY; Schema: libinv; Owner: scancodeio
--

ALTER SEQUENCE libinv.wasps_id_seq OWNED BY libinv.wasps.id;


--
-- Name: deployment_checkpoints id; Type: DEFAULT; Schema: libinv; Owner: scancodeio
--

ALTER TABLE ONLY libinv.deployment_checkpoints ALTER COLUMN id SET DEFAULT nextval('libinv.deployment_checkpoints_id_seq'::regclass);


--
-- Name: images id; Type: DEFAULT; Schema: libinv; Owner: scancodeio
--

ALTER TABLE ONLY libinv.images ALTER COLUMN id SET DEFAULT nextval('libinv.images_id_seq'::regclass);


--
-- Name: license_family id; Type: DEFAULT; Schema: libinv; Owner: scancodeio
--

ALTER TABLE ONLY libinv.license_family ALTER COLUMN id SET DEFAULT nextval('libinv.license_family_id_seq'::regclass);


--
-- Name: packages id; Type: DEFAULT; Schema: libinv; Owner: scancodeio
--

ALTER TABLE ONLY libinv.packages ALTER COLUMN id SET DEFAULT nextval('libinv.packages_id_seq'::regclass);


--
-- Name: repositories id; Type: DEFAULT; Schema: libinv; Owner: scancodeio
--

ALTER TABLE ONLY libinv.repositories ALTER COLUMN id SET DEFAULT nextval('libinv.repositories_id_seq'::regclass);


--
-- Name: sast_lob_metadata id; Type: DEFAULT; Schema: libinv; Owner: scancodeio
--

ALTER TABLE ONLY libinv.sast_lob_metadata ALTER COLUMN id SET DEFAULT nextval('libinv.sast_lob_metadata_id_seq'::regclass);


--
-- Name: wasps id; Type: DEFAULT; Schema: libinv; Owner: scancodeio
--

ALTER TABLE ONLY libinv.wasps ALTER COLUMN id SET DEFAULT nextval('libinv.wasps_id_seq'::regclass);


--
-- Name: accounts accounts_pkey; Type: CONSTRAINT; Schema: libinv; Owner: scancodeio
--

ALTER TABLE ONLY libinv.accounts
    ADD CONSTRAINT accounts_pkey PRIMARY KEY (id);


--
-- Name: actionable_package_available_versions actionable_package_available_versions_pkey; Type: CONSTRAINT; Schema: libinv; Owner: scancodeio
--

ALTER TABLE ONLY libinv.actionable_package_available_versions
    ADD CONSTRAINT actionable_package_available_versions_pkey PRIMARY KEY (uuid);


--
-- Name: deployment_checkpoints deployment_checkpoints_pkey; Type: CONSTRAINT; Schema: libinv; Owner: scancodeio
--

ALTER TABLE ONLY libinv.deployment_checkpoints
    ADD CONSTRAINT deployment_checkpoints_pkey PRIMARY KEY (id);


--
-- Name: epss epss_pkey; Type: CONSTRAINT; Schema: libinv; Owner: scancodeio
--

ALTER TABLE ONLY libinv.epss
    ADD CONSTRAINT epss_pkey PRIMARY KEY (cve);


--
-- Name: image_package_association image_package_association_pkey; Type: CONSTRAINT; Schema: libinv; Owner: scancodeio
--

ALTER TABLE ONLY libinv.image_package_association
    ADD CONSTRAINT image_package_association_pkey PRIMARY KEY (image_id, package_id);


--
-- Name: images images_pkey; Type: CONSTRAINT; Schema: libinv; Owner: scancodeio
--

ALTER TABLE ONLY libinv.images
    ADD CONSTRAINT images_pkey PRIMARY KEY (id);


--
-- Name: latest_images latest_images_pkey; Type: CONSTRAINT; Schema: libinv; Owner: scancodeio
--

ALTER TABLE ONLY libinv.latest_images
    ADD CONSTRAINT latest_images_pkey PRIMARY KEY (image_id, account_id);


--
-- Name: layers layers_pkey; Type: CONSTRAINT; Schema: libinv; Owner: scancodeio
--

ALTER TABLE ONLY libinv.layers
    ADD CONSTRAINT layers_pkey PRIMARY KEY (id, image_id, seq);


--
-- Name: license_family license_family_name_key; Type: CONSTRAINT; Schema: libinv; Owner: scancodeio
--

ALTER TABLE ONLY libinv.license_family
    ADD CONSTRAINT license_family_name_key UNIQUE (name);


--
-- Name: license_family license_family_pkey; Type: CONSTRAINT; Schema: libinv; Owner: scancodeio
--

ALTER TABLE ONLY libinv.license_family
    ADD CONSTRAINT license_family_pkey PRIMARY KEY (id);


--
-- Name: package_license_association package_license_association_pkey; Type: CONSTRAINT; Schema: libinv; Owner: scancodeio
--

ALTER TABLE ONLY libinv.package_license_association
    ADD CONSTRAINT package_license_association_pkey PRIMARY KEY (package_id, license_id);


--
-- Name: packages packages_pkey; Type: CONSTRAINT; Schema: libinv; Owner: scancodeio
--

ALTER TABLE ONLY libinv.packages
    ADD CONSTRAINT packages_pkey PRIMARY KEY (id);


--
-- Name: packages packages_purl_key; Type: CONSTRAINT; Schema: libinv; Owner: scancodeio
--

ALTER TABLE ONLY libinv.packages
    ADD CONSTRAINT packages_purl_key UNIQUE (purl);


--
-- Name: repositories repositories_pkey; Type: CONSTRAINT; Schema: libinv; Owner: scancodeio
--

ALTER TABLE ONLY libinv.repositories
    ADD CONSTRAINT repositories_pkey PRIMARY KEY (id);


--
-- Name: repository_actionable_package_versions_association repository_actionable_package_versions_association_pkey; Type: CONSTRAINT; Schema: libinv; Owner: scancodeio
--

ALTER TABLE ONLY libinv.repository_actionable_package_versions_association
    ADD CONSTRAINT repository_actionable_package_versions_association_pkey PRIMARY KEY (uuid);


--
-- Name: safe_actionable safe_actionable_package_url_key; Type: CONSTRAINT; Schema: libinv; Owner: scancodeio
--

ALTER TABLE ONLY libinv.safe_actionable
    ADD CONSTRAINT safe_actionable_package_url_key UNIQUE (package_url);


--
-- Name: safe_actionable safe_actionable_pkey; Type: CONSTRAINT; Schema: libinv; Owner: scancodeio
--

ALTER TABLE ONLY libinv.safe_actionable
    ADD CONSTRAINT safe_actionable_pkey PRIMARY KEY (uuid);


--
-- Name: sast_lob_metadata sast_lob_metadata_pkey; Type: CONSTRAINT; Schema: libinv; Owner: scancodeio
--

ALTER TABLE ONLY libinv.sast_lob_metadata
    ADD CONSTRAINT sast_lob_metadata_pkey PRIMARY KEY (id);


--
-- Name: sast_result sast_result_pkey; Type: CONSTRAINT; Schema: libinv; Owner: scancodeio
--

ALTER TABLE ONLY libinv.sast_result
    ADD CONSTRAINT sast_result_pkey PRIMARY KEY (id);


--
-- Name: secbugs secbugs_pkey; Type: CONSTRAINT; Schema: libinv; Owner: scancodeio
--

ALTER TABLE ONLY libinv.secbugs
    ADD CONSTRAINT secbugs_pkey PRIMARY KEY (id);


--
-- Name: actionable_package_available_versions uq_package_version; Type: CONSTRAINT; Schema: libinv; Owner: scancodeio
--

ALTER TABLE ONLY libinv.actionable_package_available_versions
    ADD CONSTRAINT uq_package_version UNIQUE (package_url, version);


--
-- Name: vulnerabilities vulnerabilities_pkey; Type: CONSTRAINT; Schema: libinv; Owner: scancodeio
--

ALTER TABLE ONLY libinv.vulnerabilities
    ADD CONSTRAINT vulnerabilities_pkey PRIMARY KEY (id);


--
-- Name: vulnerability_package_association vulnerability_package_association_pkey; Type: CONSTRAINT; Schema: libinv; Owner: scancodeio
--

ALTER TABLE ONLY libinv.vulnerability_package_association
    ADD CONSTRAINT vulnerability_package_association_pkey PRIMARY KEY (vulnerability_id, package_id);


--
-- Name: wasps wasps_pkey; Type: CONSTRAINT; Schema: libinv; Owner: scancodeio
--

ALTER TABLE ONLY libinv.wasps
    ADD CONSTRAINT wasps_pkey PRIMARY KEY (id);


--
-- Name: wasps wasps_uuid_key; Type: CONSTRAINT; Schema: libinv; Owner: scancodeio
--

ALTER TABLE ONLY libinv.wasps
    ADD CONSTRAINT wasps_uuid_key UNIQUE (uuid);


--
-- Name: idx_repository; Type: INDEX; Schema: libinv; Owner: scancodeio
--

CREATE INDEX idx_repository ON libinv.sast_lob_metadata USING btree (repository_id);


--
-- Name: not-null-metadata; Type: INDEX; Schema: libinv; Owner: scancodeio
--

CREATE INDEX "not-null-metadata" ON libinv.image_package_association USING btree (metadata);


--
-- Name: actionable_package_available_versions actionable_package_available_versions_actionable_id_fkey; Type: FK CONSTRAINT; Schema: libinv; Owner: scancodeio
--

ALTER TABLE ONLY libinv.actionable_package_available_versions
    ADD CONSTRAINT actionable_package_available_versions_actionable_id_fkey FOREIGN KEY (actionable_id) REFERENCES libinv.safe_actionable(uuid) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: image_package_association image_package_association_image_id_fkey; Type: FK CONSTRAINT; Schema: libinv; Owner: scancodeio
--

ALTER TABLE ONLY libinv.image_package_association
    ADD CONSTRAINT image_package_association_image_id_fkey FOREIGN KEY (image_id) REFERENCES libinv.images(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: image_package_association image_package_association_package_id_fkey; Type: FK CONSTRAINT; Schema: libinv; Owner: scancodeio
--

ALTER TABLE ONLY libinv.image_package_association
    ADD CONSTRAINT image_package_association_package_id_fkey FOREIGN KEY (package_id) REFERENCES libinv.packages(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: images images_account_id_fkey; Type: FK CONSTRAINT; Schema: libinv; Owner: scancodeio
--

ALTER TABLE ONLY libinv.images
    ADD CONSTRAINT images_account_id_fkey FOREIGN KEY (account_id) REFERENCES libinv.accounts(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: images images_base_image_id_fkey; Type: FK CONSTRAINT; Schema: libinv; Owner: scancodeio
--

ALTER TABLE ONLY libinv.images
    ADD CONSTRAINT images_base_image_id_fkey FOREIGN KEY (base_image_id) REFERENCES libinv.images(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: images images_parent_image_id_fkey; Type: FK CONSTRAINT; Schema: libinv; Owner: scancodeio
--

ALTER TABLE ONLY libinv.images
    ADD CONSTRAINT images_parent_image_id_fkey FOREIGN KEY (parent_image_id) REFERENCES libinv.images(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: images images_repository_id_fkey; Type: FK CONSTRAINT; Schema: libinv; Owner: scancodeio
--

ALTER TABLE ONLY libinv.images
    ADD CONSTRAINT images_repository_id_fkey FOREIGN KEY (repository_id) REFERENCES libinv.repositories(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: images images_wasp_id_fkey; Type: FK CONSTRAINT; Schema: libinv; Owner: scancodeio
--

ALTER TABLE ONLY libinv.images
    ADD CONSTRAINT images_wasp_id_fkey FOREIGN KEY (wasp_id) REFERENCES libinv.wasps(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: latest_images latest_images_account_id_fkey; Type: FK CONSTRAINT; Schema: libinv; Owner: scancodeio
--

ALTER TABLE ONLY libinv.latest_images
    ADD CONSTRAINT latest_images_account_id_fkey FOREIGN KEY (account_id) REFERENCES libinv.accounts(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: latest_images latest_images_image_id_fkey; Type: FK CONSTRAINT; Schema: libinv; Owner: scancodeio
--

ALTER TABLE ONLY libinv.latest_images
    ADD CONSTRAINT latest_images_image_id_fkey FOREIGN KEY (image_id) REFERENCES libinv.images(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: layers layers_image_id_fkey; Type: FK CONSTRAINT; Schema: libinv; Owner: scancodeio
--

ALTER TABLE ONLY libinv.layers
    ADD CONSTRAINT layers_image_id_fkey FOREIGN KEY (image_id) REFERENCES libinv.images(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: package_license_association package_license_association_license_id_fkey; Type: FK CONSTRAINT; Schema: libinv; Owner: scancodeio
--

ALTER TABLE ONLY libinv.package_license_association
    ADD CONSTRAINT package_license_association_license_id_fkey FOREIGN KEY (license_id) REFERENCES libinv.license_family(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: package_license_association package_license_association_package_id_fkey; Type: FK CONSTRAINT; Schema: libinv; Owner: scancodeio
--

ALTER TABLE ONLY libinv.package_license_association
    ADD CONSTRAINT package_license_association_package_id_fkey FOREIGN KEY (package_id) REFERENCES libinv.packages(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: repository_actionable_package_versions_association repository_actionable_package_actionable_package_version_i_fkey; Type: FK CONSTRAINT; Schema: libinv; Owner: scancodeio
--

ALTER TABLE ONLY libinv.repository_actionable_package_versions_association
    ADD CONSTRAINT repository_actionable_package_actionable_package_version_i_fkey FOREIGN KEY (actionable_package_version_id) REFERENCES libinv.actionable_package_available_versions(uuid) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: repository_actionable_package_versions_association repository_actionable_package_versions_assoc_repository_id_fkey; Type: FK CONSTRAINT; Schema: libinv; Owner: scancodeio
--

ALTER TABLE ONLY libinv.repository_actionable_package_versions_association
    ADD CONSTRAINT repository_actionable_package_versions_assoc_repository_id_fkey FOREIGN KEY (repository_id) REFERENCES libinv.repositories(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: repository_actionable_package_versions_association repository_actionable_package_versions_associati_wasp_uuid_fkey; Type: FK CONSTRAINT; Schema: libinv; Owner: scancodeio
--

ALTER TABLE ONLY libinv.repository_actionable_package_versions_association
    ADD CONSTRAINT repository_actionable_package_versions_associati_wasp_uuid_fkey FOREIGN KEY (wasp_uuid) REFERENCES libinv.wasps(uuid) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: sast_lob_metadata sast_lob_metadata_repository_id_fkey; Type: FK CONSTRAINT; Schema: libinv; Owner: scancodeio
--

ALTER TABLE ONLY libinv.sast_lob_metadata
    ADD CONSTRAINT sast_lob_metadata_repository_id_fkey FOREIGN KEY (repository_id) REFERENCES libinv.repositories(id) ON UPDATE CASCADE;


--
-- Name: sast_result sast_result_lob_id_fkey; Type: FK CONSTRAINT; Schema: libinv; Owner: scancodeio
--

ALTER TABLE ONLY libinv.sast_result
    ADD CONSTRAINT sast_result_lob_id_fkey FOREIGN KEY (lob_id) REFERENCES libinv.sast_lob_metadata(id) ON UPDATE CASCADE;


--
-- Name: sast_result sast_result_wasp_id_fkey; Type: FK CONSTRAINT; Schema: libinv; Owner: scancodeio
--

ALTER TABLE ONLY libinv.sast_result
    ADD CONSTRAINT sast_result_wasp_id_fkey FOREIGN KEY (wasp_id) REFERENCES libinv.wasps(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: secbugs secbugs_repository_id_fkey; Type: FK CONSTRAINT; Schema: libinv; Owner: scancodeio
--

ALTER TABLE ONLY libinv.secbugs
    ADD CONSTRAINT secbugs_repository_id_fkey FOREIGN KEY (repository_id) REFERENCES libinv.repositories(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: vulnerability_package_association vulnerability_package_association_package_id_fkey; Type: FK CONSTRAINT; Schema: libinv; Owner: scancodeio
--

ALTER TABLE ONLY libinv.vulnerability_package_association
    ADD CONSTRAINT vulnerability_package_association_package_id_fkey FOREIGN KEY (package_id) REFERENCES libinv.packages(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: vulnerability_package_association vulnerability_package_association_vulnerability_id_fkey; Type: FK CONSTRAINT; Schema: libinv; Owner: scancodeio
--

ALTER TABLE ONLY libinv.vulnerability_package_association
    ADD CONSTRAINT vulnerability_package_association_vulnerability_id_fkey FOREIGN KEY (vulnerability_id) REFERENCES libinv.vulnerabilities(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: wasps wasps_repository_id_fkey; Type: FK CONSTRAINT; Schema: libinv; Owner: scancodeio
--

ALTER TABLE ONLY libinv.wasps
    ADD CONSTRAINT wasps_repository_id_fkey FOREIGN KEY (repository_id) REFERENCES libinv.repositories(id) ON UPDATE CASCADE;


--
-- PostgreSQL database dump complete
--

\unrestrict OGpOw5cgpr9CaXCX1DPnDB6QeuQjK3sdaQJNhweVYvbhLrinh6Bx199JHLPVEA5

