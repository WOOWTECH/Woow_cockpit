"""Reviewed PostgreSQL definitions for Memories; no program text is taken from a backup.

Source: pulsejet/memories v11.1.4, commit 3ec040e55d2cfc8bd0e339c6338946d1513d15ae (read 2026-11-27).
lib/Db/FilecacheTriggers.php blob d7925012010dc3b35ec994f659776ed99f7b4e68; hashes and system-config proof in
snippets/focus-nextcloud/vendor.json. This setting is IConfig system config (config.php), not oc_appconfig.
The vendor updates Memories' parent on every filecache update. Qualify public objects, pin name resolution and retain
SECURITY INVOKER. The ordinary data loader creates these only after the restored database passes the hostile-object gate.
"""
from .ha_odoo import sql_literal

CONFIG_KEY = 'memories.db.triggers.fcu'
BODY = """BEGIN
    UPDATE public.oc_memories SET parent = NEW.parent WHERE fileid = NEW.fileid;
    RETURN NEW;
END;
"""
CREATE_SQL = ("CREATE OR REPLACE FUNCTION public.memories_fcu_fun() RETURNS trigger\n"
              "LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $woowbk$\n" + BODY
              + "$woowbk$;\nCREATE TRIGGER memories_fcu_trg AFTER UPDATE ON public.oc_filecache\n"
                "FOR EACH ROW EXECUTE FUNCTION public.memories_fcu_fun();\n")
# Catalogs only. Four integer columns on two ordinary tables, so the fixed UPDATE cannot dispatch to backup-defined types.
TABLES_SQL = """SELECT to_json(count(*) = 4) FROM pg_attribute a
JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public' AND c.relname IN ('oc_filecache', 'oc_memories') AND c.relkind = 'r'
AND a.attname IN ('fileid', 'parent') AND NOT a.attisdropped AND a.attnum > 0
AND a.atttypid IN ('pg_catalog.int4'::regtype, 'pg_catalog.int8'::regtype)"""


def verify_sql(role):
    """Catalog proof of the exact body, owner, invoker rights, language, search path and trigger firing conditions.

    SHAPE_SQL additionally requires exactly one non-extension function and one non-internal trigger in the whole database.
    No backup function is invoked to validate these definitions.
    """
    return f"""WITH f AS (SELECT p.oid FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
JOIN pg_language l ON l.oid = p.prolang
WHERE n.nspname = 'public' AND p.proname = 'memories_fcu_fun' AND p.prokind = 'f'
AND p.pronargs = 0 AND p.pronargdefaults = 0 AND p.proallargtypes IS NULL AND NOT p.proretset
AND p.prorettype = 'pg_catalog.trigger'::regtype AND l.lanname = 'plpgsql' AND l.lanpltrusted
AND NOT p.prosecdef AND NOT p.proleakproof AND NOT p.proisstrict AND p.provolatile = 'v' AND p.proparallel = 'u'
AND p.prosupport = 0 AND p.probin IS NULL AND p.proacl IS NULL
AND p.proowner = (SELECT oid FROM pg_roles WHERE rolname = {sql_literal(role)})
AND p.proconfig = ARRAY['search_path=pg_catalog'] AND p.prosrc = {sql_literal(chr(10) + BODY)})
SELECT to_json((SELECT count(*) FROM f) = 1 AND (SELECT count(*) FROM pg_trigger t
JOIN pg_class c ON c.oid = t.tgrelid JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public' AND c.relname = 'oc_filecache' AND t.tgname = 'memories_fcu_trg'
AND t.tgfoid IN (SELECT oid FROM f) AND t.tgtype = 17 AND t.tgenabled = 'O' AND NOT t.tgisinternal
AND t.tgnargs = 0 AND octet_length(t.tgargs) = 0 AND t.tgattr = ''::int2vector AND t.tgqual IS NULL
AND t.tgconstraint = 0 AND t.tgconstrrelid = 0 AND t.tgconstrindid = 0 AND t.tgparentid = 0
AND NOT t.tgdeferrable AND NOT t.tginitdeferred AND t.tgoldtable IS NULL AND t.tgnewtable IS NULL) = 1)"""
