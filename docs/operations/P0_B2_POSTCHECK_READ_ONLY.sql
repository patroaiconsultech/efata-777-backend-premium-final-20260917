-- EFATA 777 / DG-01 P0 B2 — SOMENTE LEITURA / STAGING
-- Operador deve confirmar RAILWAY_ENVIRONMENT_NAME=staging-web01 e
-- PostgreSQL system_identifier=7696494375094112315 em cada sessão.
-- NÃO executar alteração de schema nem escrever em produção.
SELECT current_database() AS database_name,
       system_identifier::text AS pg_system_identifier
FROM pg_control_system();

SELECT version_num FROM public.alembic_version;
SELECT table_schema, data_type, character_maximum_length, is_nullable
FROM information_schema.columns
WHERE table_schema='public'
  AND table_name='alembic_version' AND column_name='version_num';

WITH expected(table_name, column_name, expected_revision) AS (
    VALUES
    ('thread_participants','allowed_agent_ids','014'),
    ('thread_participants','can_read_messages','015'),
    ('thread_participants','can_write_messages','015'),
    ('thread_participants','access_expires_at','016'),
    ('thread_invitations','allowed_agent_ids','014'),
    ('thread_invitations','can_read_messages','015'),
    ('thread_invitations','can_write_messages','015'),
    ('thread_invitations','access_duration_hours','016')
)
SELECT e.table_name, e.column_name, e.expected_revision,
       CASE WHEN c.column_name IS NULL THEN 'MISSING' ELSE 'PRESENT' END AS state,
       c.data_type, c.udt_name, c.is_nullable, c.column_default
FROM expected e
LEFT JOIN information_schema.columns c
ON c.table_schema='public'
 AND c.table_name=e.table_name AND c.column_name=e.column_name
ORDER BY e.table_name, e.expected_revision, e.column_name;

SELECT c.conname, pg_get_constraintdef(c.oid) AS definition
FROM pg_constraint c JOIN pg_class t ON t.oid=c.conrelid
 JOIN pg_namespace n ON n.oid=t.relnamespace
WHERE n.nspname='public' AND t.relname='thread_invitations'
  AND c.conname='ck_thread_invitation_access_duration';

-- Comparar quantidades sintéticas antes/depois sem expor conteúdo de conversas.
SELECT 'thread_participants' AS table_name, COUNT(*) AS row_count
FROM public.thread_participants
UNION ALL
SELECT 'thread_invitations', COUNT(*) FROM public.thread_invitations;
