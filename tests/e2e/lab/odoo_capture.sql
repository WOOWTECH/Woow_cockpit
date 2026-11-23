BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL TIME ZONE 'UTC';
SET LOCAL DateStyle TO 'ISO, YMD';
SET LOCAL extra_float_digits TO 3;
SET LOCAL statement_timeout TO '120s';
SET LOCAL lock_timeout TO '5s';
SELECT jsonb_build_object('kind','capture_metadata','schema_version',2,
  'database',current_database(),'server_version',current_setting('server_version'),
  'encoding',current_setting('server_encoding'),'snapshot',txid_current_snapshot()::text,
  'captured_at',transaction_timestamp(),'snapshot_at',clock_timestamp(),
  'other_clients',(SELECT count(*) FROM pg_stat_activity WHERE datname=current_database()
                   AND pid<>pg_backend_pid() AND backend_type='client backend'));
-- Every user table in the same snapshot, with exactly ha_import_e2e.FINGERPRINT_SQL's count and md5.
SELECT jsonb_build_object('kind','table_fingerprint','line',format('%s.%s %s %s', schemaname, relname,
  (xpath('/row/c/text()', query_to_xml(format('select count(*) as c from %I.%I', schemaname, relname),
   false, true, '')))[1]::text,
  (xpath('/row/m/text()', query_to_xml(format(
   'select md5(coalesce(string_agg(t::text, %L order by t::text), %L)) as m from %I.%I t',
   E'\n', '', schemaname, relname), false, true, '')))[1]::text))
FROM pg_stat_user_tables ORDER BY schemaname, relname;
SELECT jsonb_build_object('kind','column','table',n.nspname||'.'||c.relname,
  'position',a.attnum,'name',a.attname,'type',format_type(a.atttypid,a.atttypmod),
  'not_null',a.attnotnull,
  'identity',a.attidentity,'generated',a.attgenerated,
  'collation',CASE WHEN a.attcollation=0 THEN NULL ELSE a.attcollation::regcollation::text END,
  'default_sha256',CASE WHEN ad.adbin IS NULL THEN NULL ELSE
    encode(sha256(convert_to(pg_get_expr(ad.adbin,ad.adrelid),'UTF8')),'hex') END,
  'primary_key',EXISTS (
    SELECT 1 FROM pg_index i WHERE i.indrelid=c.oid AND i.indisprimary AND a.attnum=ANY(i.indkey)))
FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
JOIN pg_attribute a ON a.attrelid=c.oid
LEFT JOIN pg_attrdef ad ON ad.adrelid=c.oid AND ad.adnum=a.attnum
WHERE n.nspname='public' AND c.relname IN
 ('ir_config_parameter','ir_cron','ir_cron_progress','bus_bus','mail_mail','mail_message')
AND a.attnum>0 AND NOT a.attisdropped ORDER BY c.relname,a.attnum;
-- to_jsonb covers ALL real columns; no hard-coded list drops unknown fields.
-- Digests are change locators, not proof of legitimate changes or secret storage.
-- `safe` is a small plaintext projection of non-secret columns for row evidence: configuration values only for
-- the import settings keys and the bus retention (odoo_explain.PLAIN_KEYS), never bus messages or channels, never
-- mail subjects, bodies or addresses.
WITH rows(table_name, row_data) AS (
 SELECT 'public.ir_config_parameter',to_jsonb(t) FROM public.ir_config_parameter t
 UNION ALL SELECT 'public.ir_cron',to_jsonb(t) FROM public.ir_cron t
 UNION ALL SELECT 'public.ir_cron_progress',to_jsonb(t) FROM public.ir_cron_progress t
 UNION ALL SELECT 'public.bus_bus',to_jsonb(t) FROM public.bus_bus t
 UNION ALL SELECT 'public.mail_mail',to_jsonb(t) FROM public.mail_mail t
 UNION ALL SELECT 'public.mail_message',to_jsonb(t) FROM public.mail_message t
)
SELECT jsonb_build_object('kind','row','table',table_name,'id',row_data->'id',
 'row_sha256',encode(sha256(convert_to(row_data::text,'UTF8')),'hex'),
 'field_sha256',(SELECT jsonb_object_agg(key,encode(sha256(convert_to(value::text,'UTF8')),'hex'))
                 FROM jsonb_each(row_data)),
 'safe',CASE table_name
  WHEN 'public.ir_config_parameter' THEN jsonb_build_object('key',row_data->'key',
   'create_date',row_data->'create_date','write_date',row_data->'write_date',
   'value',CASE WHEN row_data->>'key' IN ('web.base.url','web.base.url.freeze','woow_paas_platform.upgrade_done',
     'woow_paas_platform.upgrade_attempt','bus.gc_retention_seconds') THEN row_data->'value' END)
  WHEN 'public.ir_cron' THEN jsonb_build_object(
   'xmlid',(SELECT to_jsonb(d.module||'.'||d.name) FROM public.ir_model_data d
            WHERE d.model='ir.cron' AND d.res_id=(row_data->>'id')::integer ORDER BY d.id LIMIT 1),
   'cron_name',row_data->'cron_name','active',row_data->'active','interval_number',row_data->'interval_number',
   'interval_type',row_data->'interval_type','nextcall',row_data->'nextcall','lastcall',row_data->'lastcall',
   'failure_count',row_data->'failure_count','first_failure_date',row_data->'first_failure_date',
   'write_date',row_data->'write_date')
  WHEN 'public.ir_cron_progress' THEN jsonb_build_object('cron_id',row_data->'cron_id','done',row_data->'done',
   'remaining',row_data->'remaining','deactivate',row_data->'deactivate',
   'timed_out_counter',row_data->'timed_out_counter','create_date',row_data->'create_date',
   'write_date',row_data->'write_date')
  WHEN 'public.mail_mail' THEN jsonb_build_object('mail_message_id',row_data->'mail_message_id',
   'state',row_data->'state','create_date',row_data->'create_date','write_date',row_data->'write_date')
  WHEN 'public.mail_message' THEN jsonb_build_object('model',row_data->'model','res_id',row_data->'res_id',
   'message_type',row_data->'message_type','create_date',row_data->'create_date','write_date',row_data->'write_date')
  ELSE jsonb_build_object('create_date',row_data->'create_date') END)
FROM rows ORDER BY table_name,(row_data->>'id')::bigint;
SELECT jsonb_build_object('kind','count','table','public.ir_config_parameter','count',count(*)) FROM public.ir_config_parameter
UNION ALL SELECT jsonb_build_object('kind','count','table','public.ir_cron','count',count(*)) FROM public.ir_cron
UNION ALL SELECT jsonb_build_object('kind','count','table','public.ir_cron_progress','count',count(*)) FROM public.ir_cron_progress
UNION ALL SELECT jsonb_build_object('kind','count','table','public.bus_bus','count',count(*)) FROM public.bus_bus
UNION ALL SELECT jsonb_build_object('kind','count','table','public.mail_mail','count',count(*)) FROM public.mail_mail
UNION ALL SELECT jsonb_build_object('kind','count','table','public.mail_message','count',count(*)) FROM public.mail_message;
COMMIT;
