-- Additive learning storage; runtime actor identity is supplied by scoped API auth.
CREATE TABLE learning_lessons (
 id UUID PRIMARY KEY, owner_id UUID NOT NULL, repository TEXT NOT NULL,
 component TEXT NOT NULL, idempotency_key TEXT NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 UNIQUE(owner_id,idempotency_key)
);
CREATE TABLE learning_revisions (
 id UUID PRIMARY KEY, lesson_id UUID NOT NULL REFERENCES learning_lessons(id),
 revision INTEGER NOT NULL CHECK(revision>0),
 status TEXT NOT NULL CHECK(status IN ('pending','active','superseded','deprecated')),
 payload JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 last_verified TIMESTAMPTZ, UNIQUE(lesson_id,revision)
);
CREATE UNIQUE INDEX learning_one_active_revision ON learning_revisions(lesson_id) WHERE status='active';
CREATE TABLE learning_records (
 id UUID PRIMARY KEY, revision_id UUID NOT NULL REFERENCES learning_revisions(id),
 actor_id UUID NOT NULL, kind TEXT NOT NULL CHECK(kind IN ('review','decision','routing','escalation')),
 payload JSONB NOT NULL, idempotency_key TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 UNIQUE(revision_id,actor_id,idempotency_key)
);
CREATE INDEX learning_lookup ON learning_lessons(owner_id,repository,component);
CREATE INDEX learning_revision_status ON learning_revisions(status,last_verified DESC);
CREATE FUNCTION clawforge_learning_revision_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF OLD.id IS DISTINCT FROM NEW.id OR OLD.lesson_id IS DISTINCT FROM NEW.lesson_id
 OR OLD.revision IS DISTINCT FROM NEW.revision OR OLD.payload IS DISTINCT FROM NEW.payload
 OR OLD.created_at IS DISTINCT FROM NEW.created_at THEN
  RAISE EXCEPTION 'learning revision snapshot is immutable';
 END IF;
 IF OLD.status IN ('superseded','deprecated') AND OLD.status IS DISTINCT FROM NEW.status THEN
  RAISE EXCEPTION 'terminal learning revision is immutable';
 END IF;
 NEW.updated_at := NOW();
 RETURN NEW;
END; $$;
CREATE TRIGGER learning_revision_immutable BEFORE UPDATE ON learning_revisions
 FOR EACH ROW EXECUTE FUNCTION clawforge_learning_revision_immutable();

-- Stable actor links are created explicitly during credential rotation; names are
-- not identities. Existing credentials retain their UUID as the initial actor.
CREATE TABLE learning_actor_tokens (
 token_id UUID PRIMARY KEY REFERENCES agent_tokens(id), actor_id UUID NOT NULL
);
INSERT INTO learning_actor_tokens SELECT id,id FROM agent_tokens;
CREATE TABLE learning_curator_grants (
 owner_id UUID NOT NULL, reviewer_id UUID NOT NULL,
 PRIMARY KEY(owner_id,reviewer_id), CHECK(owner_id<>reviewer_id)
);
-- Only trusted CI/admin integration may create attestations. There is no agent
-- HTTP endpoint for attesting caller-supplied passed flags or granting curators.
CREATE TABLE learning_verified_evidence (
 owner_id UUID NOT NULL, repository TEXT NOT NULL, commit_hash TEXT NOT NULL,
 test_name TEXT NOT NULL, artifact_sha256 TEXT NOT NULL,
 verifier_id UUID NOT NULL, verified_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 PRIMARY KEY(owner_id,repository,commit_hash,test_name,artifact_sha256),
 CHECK(owner_id<>verifier_id)
);

-- Explicit generic applicability can match unspecified non-version fields.
-- A versioned query never treats missing version data as applicable: a generic
-- rule must opt in with versions {"*":"*"}. Conflicting explicit fields reject.
CREATE FUNCTION clawforge_learning_context_matches(context JSONB, requested JSONB)
RETURNS BOOLEAN LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE k TEXT; v JSONB; vk TEXT; vv JSONB; generic BOOLEAN;
BEGIN
 generic := COALESCE((context->>'generic')::boolean,FALSE);
 FOR k,v IN SELECT * FROM jsonb_each(requested) LOOP
  IF k='versions' THEN
   FOR vk,vv IN SELECT * FROM jsonb_each(v) LOOP
    IF context->'versions'->vk IS NOT DISTINCT FROM vv THEN CONTINUE; END IF;
    IF generic AND context->'versions'->>'*'='*' AND context->'versions'->vk IS NULL THEN CONTINUE; END IF;
    RETURN FALSE;
   END LOOP;
  ELSIF k='files' THEN
   IF context->'files' @> v THEN CONTINUE; END IF;
   IF generic AND COALESCE(jsonb_array_length(context->'files'),0)=0 THEN CONTINUE; END IF;
   RETURN FALSE;
  ELSE
   IF context->k IS NOT DISTINCT FROM v THEN CONTINUE; END IF;
   IF generic AND (context->k IS NULL OR context->k='null'::jsonb) THEN CONTINUE; END IF;
   RETURN FALSE;
  END IF;
 END LOOP;
 RETURN TRUE;
END; $$;
