-- Migration: rename session_id to user_id in article_read_state
-- Run once against an existing database. Safe to re-run (checks column existence).

DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'article_read_state' AND column_name = 'session_id'
  ) THEN
    DROP INDEX IF EXISTS idx_read_state_session;
    ALTER TABLE article_read_state
      DROP CONSTRAINT IF EXISTS article_read_state_article_id_session_id_key;

    ALTER TABLE article_read_state RENAME COLUMN session_id TO user_id;

    -- Old session UUIDs are meaningless after migration; clear them
    TRUNCATE article_read_state;

    ALTER TABLE article_read_state
      ADD CONSTRAINT article_read_state_article_id_user_id_key UNIQUE (article_id, user_id);
    CREATE INDEX idx_read_state_user ON article_read_state (user_id);
  END IF;
END $$;
