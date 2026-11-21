BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL TIME ZONE 'UTC';
SET LOCAL DateStyle TO 'ISO, YMD';
SET LOCAL extra_float_digits TO 3;
SET LOCAL statement_timeout TO '60s';
SET LOCAL lock_timeout TO '5s';
SELECT jsonb_build_object('kind','capture_metadata','schema_version',1,
  'database',current_database(),'server_version',current_setting('server_version'),
  'encoding',current_setting('server_encoding'),'snapshot',txid_current_snapshot()::text,
  'captured_at',transaction_timestamp(),
  'other_clients',(SELECT count(*) FROM pg_stat_activity WHERE datname=current_database()
                   AND pid<>pg_backend_pid() AND backend_type='client backend'));
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
 ('ir_config_parameter','ir_cron','ir_cron_progress','bus_bus')
AND a.attnum>0 AND NOT a.attisdropped ORDER BY c.relname,a.attnum;
-- to_jsonb covers ALL real columns; no hard-coded list drops unknown fields.
-- Digests are change locators, not proof of legitimate changes or secret storage.
WITH rows(table_name, row_data) AS (
 SELECT 'public.ir_config_parameter',to_jsonb(t) FROM public.ir_config_parameter t
 UNION ALL SELECT 'public.ir_cron',to_jsonb(t) FROM public.ir_cron t
 UNION ALL SELECT 'public.ir_cron_progress',to_jsonb(t) FROM public.ir_cron_progress t
 UNION ALL SELECT 'public.bus_bus',to_jsonb(t) FROM public.bus_bus t
)
SELECT jsonb_build_object('kind','row','table',table_name,'id',row_data->'id',
 'row_sha256',encode(sha256(convert_to(row_data::text,'UTF8')),'hex'),
 'field_sha256',(SELECT jsonb_object_agg(key,encode(sha256(convert_to(value::text,'UTF8')),'hex'))
                 FROM jsonb_each(row_data)))
FROM rows ORDER BY table_name,row_data->>'id';
SELECT jsonb_build_object('kind','count','table','public.ir_config_parameter','count',count(*)) FROM public.ir_config_parameter
UNION ALL SELECT jsonb_build_object('kind','count','table','public.ir_cron','count',count(*)) FROM public.ir_cron
UNION ALL SELECT jsonb_build_object('kind','count','table','public.ir_cron_progress','count',count(*)) FROM public.ir_cron_progress
UNION ALL SELECT jsonb_build_object('kind','count','table','public.bus_bus','count',count(*)) FROM public.bus_bus;
COMMIT;
