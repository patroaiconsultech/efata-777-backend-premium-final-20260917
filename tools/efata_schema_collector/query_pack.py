from __future__ import annotations

from dataclasses import dataclass

from .canonical import sha256_canonical

QUERY_PACK_VERSION = "EFATA-PG-QUERY-PACK-1"


@dataclass(frozen=True)
class QuerySpec:
    name: str
    sql: str
    namespace_scoped: bool = False


QUERY_SPECS: tuple[QuerySpec, ...] = (
    QuerySpec(
        "meta.snapshot",
        """
        SELECT
            pg_catalog.current_database() AS database_name,
            pg_catalog.current_setting('server_version') AS server_version,
            pg_catalog.current_setting('server_version_num') AS server_version_num,
            pg_catalog.pg_backend_pid() AS backend_pid,
            pg_catalog.transaction_timestamp()::text AS transaction_started_at,
            pg_catalog.pg_current_snapshot()::text AS transaction_snapshot
        """,
    ),
    QuerySpec(
        "catalog.namespaces",
        """
        SELECT
            n.oid,
            n.nspname AS schema_name,
            r.rolname AS owner_name,
            EXISTS (
                SELECT 1
                FROM pg_catalog.pg_depend d
                JOIN pg_catalog.pg_extension e ON e.oid = d.refobjid
                WHERE d.classid = 'pg_catalog.pg_namespace'::pg_catalog.regclass
                  AND d.objid = n.oid
                  AND d.deptype = 'e'
            ) AS extension_owned
        FROM pg_catalog.pg_namespace n
        JOIN pg_catalog.pg_roles r ON r.oid = n.nspowner
        WHERE n.nspname = ANY(%s)
        ORDER BY n.nspname
        """,
        True,
    ),
    QuerySpec(
        "catalog.relations",
        """
        SELECT
            c.oid,
            n.nspname AS schema_name,
            c.relname AS object_name,
            c.relkind,
            r.rolname AS owner_name,
            c.relpersistence,
            c.relrowsecurity,
            c.relforcerowsecurity,
            c.relispartition,
            CASE WHEN c.relispartition THEN pg_catalog.pg_get_expr(c.relpartbound, c.oid) ELSE NULL END AS partition_bound,
            CASE WHEN c.relkind = 'p' THEN pg_catalog.pg_get_partkeydef(c.oid) ELSE NULL END AS partition_key,
            EXISTS (
                SELECT 1
                FROM pg_catalog.pg_depend d
                JOIN pg_catalog.pg_extension e ON e.oid = d.refobjid
                WHERE d.classid = 'pg_catalog.pg_class'::pg_catalog.regclass
                  AND d.objid = c.oid
                  AND d.deptype = 'e'
            ) AS extension_owned
        FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        JOIN pg_catalog.pg_roles r ON r.oid = c.relowner
        WHERE n.nspname = ANY(%s)
          AND c.relkind IN ('r','p','v','m','S','f')
        ORDER BY n.nspname, c.relname, c.relkind
        """,
        True,
    ),
    QuerySpec(
        "catalog.columns",
        """
        SELECT
            c.oid AS relation_oid,
            n.nspname AS schema_name,
            c.relname AS relation_name,
            a.attnum,
            a.attname AS column_name,
            pg_catalog.format_type(a.atttypid, a.atttypmod) AS formatted_type,
            NOT a.attnotnull AS nullable,
            a.attidentity,
            a.attgenerated,
            CASE WHEN ad.oid IS NULL THEN NULL
                 ELSE pg_catalog.pg_get_expr(ad.adbin, ad.adrelid) END AS default_expression,
            CASE WHEN a.attcollation = 0 THEN NULL
                 ELSE quote_ident(cn.nspname) || '.' || quote_ident(coll.collname) END AS collation
        FROM pg_catalog.pg_attribute a
        JOIN pg_catalog.pg_class c ON c.oid = a.attrelid
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        LEFT JOIN pg_catalog.pg_attrdef ad ON ad.adrelid = a.attrelid AND ad.adnum = a.attnum
        LEFT JOIN pg_catalog.pg_collation coll ON coll.oid = a.attcollation
        LEFT JOIN pg_catalog.pg_namespace cn ON cn.oid = coll.collnamespace
        WHERE n.nspname = ANY(%s)
          AND c.relkind IN ('r','p','v','m','f')
          AND a.attnum > 0
          AND NOT a.attisdropped
        ORDER BY n.nspname, c.relname, a.attnum
        """,
        True,
    ),
    QuerySpec(
        "catalog.constraints",
        """
        SELECT
            con.oid,
            n.nspname AS schema_name,
            c.relname AS relation_name,
            con.conname AS constraint_name,
            con.contype,
            con.condeferrable,
            con.condeferred,
            con.convalidated,
            con.confmatchtype,
            con.confupdtype,
            con.confdeltype,
            pg_catalog.pg_get_constraintdef(con.oid, true) AS definition
        FROM pg_catalog.pg_constraint con
        JOIN pg_catalog.pg_class c ON c.oid = con.conrelid
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = ANY(%s)
        ORDER BY n.nspname, c.relname, con.conname
        """,
        True,
    ),
    QuerySpec(
        "catalog.indexes",
        """
        SELECT
            i.indexrelid AS index_oid,
            tn.nspname AS schema_name,
            t.relname AS relation_name,
            ix.relname AS index_name,
            am.amname AS access_method,
            i.indisunique,
            i.indisprimary,
            i.indisexclusion,
            i.indimmediate,
            i.indisvalid,
            i.indisready,
            i.indislive,
            i.indkey::text AS indkey,
            i.indcollation::text AS indcollation,
            i.indclass::text AS indclass,
            i.indoption::text AS indoption,
            CASE WHEN i.indexprs IS NULL THEN NULL
                 ELSE pg_catalog.pg_get_expr(i.indexprs, i.indrelid) END AS expression,
            CASE WHEN i.indpred IS NULL THEN NULL
                 ELSE pg_catalog.pg_get_expr(i.indpred, i.indrelid) END AS predicate,
            pg_catalog.pg_get_indexdef(i.indexrelid) AS definition
        FROM pg_catalog.pg_index i
        JOIN pg_catalog.pg_class t ON t.oid = i.indrelid
        JOIN pg_catalog.pg_namespace tn ON tn.oid = t.relnamespace
        JOIN pg_catalog.pg_class ix ON ix.oid = i.indexrelid
        JOIN pg_catalog.pg_am am ON am.oid = ix.relam
        WHERE tn.nspname = ANY(%s)
        ORDER BY tn.nspname, t.relname, ix.relname
        """,
        True,
    ),
    QuerySpec(
        "catalog.types",
        """
        SELECT
            t.oid,
            n.nspname AS schema_name,
            t.typname AS type_name,
            t.typtype,
            t.typcategory,
            t.typnotnull,
            CASE WHEN t.typbasetype = 0 THEN NULL
                 ELSE pg_catalog.format_type(t.typbasetype, t.typtypmod) END AS base_type,
            t.typdefault,
            COALESCE((
                SELECT pg_catalog.array_agg(e.enumlabel ORDER BY e.enumsortorder)
                FROM pg_catalog.pg_enum e
                WHERE e.enumtypid = t.oid
            ), ARRAY[]::text[]) AS enum_labels
        FROM pg_catalog.pg_type t
        JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace
        WHERE n.nspname = ANY(%s)
          AND t.typtype IN ('c','d','e','r','m')
        ORDER BY n.nspname, t.typname
        """,
        True,
    ),
    QuerySpec(
        "catalog.sequences",
        """
        SELECT
            c.oid,
            n.nspname AS schema_name,
            c.relname AS sequence_name,
            r.rolname AS owner_name,
            pg_catalog.format_type(s.seqtypid, NULL) AS data_type,
            s.seqstart,
            s.seqincrement,
            s.seqmax,
            s.seqmin,
            s.seqcache,
            s.seqcycle,
            CASE WHEN d.refobjid IS NULL THEN NULL
                 ELSE rn.nspname || '.' || rc.relname || '.' || a.attname END AS owned_by
        FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        JOIN pg_catalog.pg_roles r ON r.oid = c.relowner
        JOIN pg_catalog.pg_sequence s ON s.seqrelid = c.oid
        LEFT JOIN pg_catalog.pg_depend d
          ON d.classid = 'pg_catalog.pg_class'::pg_catalog.regclass
         AND d.objid = c.oid
         AND d.deptype IN ('a','i')
        LEFT JOIN pg_catalog.pg_class rc ON rc.oid = d.refobjid
        LEFT JOIN pg_catalog.pg_namespace rn ON rn.oid = rc.relnamespace
        LEFT JOIN pg_catalog.pg_attribute a ON a.attrelid = d.refobjid AND a.attnum = d.refobjsubid
        WHERE n.nspname = ANY(%s)
        ORDER BY n.nspname, c.relname
        """,
        True,
    ),
    QuerySpec(
        "catalog.functions",
        """
        SELECT
            p.oid,
            n.nspname AS schema_name,
            p.proname AS function_name,
            pg_catalog.pg_get_function_identity_arguments(p.oid) AS identity_arguments,
            pg_catalog.pg_get_function_result(p.oid) AS result_type,
            l.lanname AS language,
            p.prokind,
            p.prosecdef,
            p.proleakproof,
            p.proisstrict,
            p.provolatile,
            p.proparallel,
            p.proconfig,
            p.prosrc,
            p.probin,
            (p.prosqlbody IS NOT NULL) AS has_prosqlbody,
            pg_catalog.pg_get_functiondef(p.oid) AS function_definition,
            r.rolname AS owner_name
        FROM pg_catalog.pg_proc p
        JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
        JOIN pg_catalog.pg_language l ON l.oid = p.prolang
        JOIN pg_catalog.pg_roles r ON r.oid = p.proowner
        WHERE n.nspname = ANY(%s)
          AND p.prokind IN ('f','p')
        ORDER BY n.nspname, p.proname, pg_catalog.pg_get_function_identity_arguments(p.oid)
        """,
        True,
    ),
    QuerySpec(
        "catalog.views",
        """
        SELECT
            c.oid,
            n.nspname AS schema_name,
            c.relname AS view_name,
            c.relkind,
            pg_catalog.pg_get_viewdef(c.oid, true) AS definition
        FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = ANY(%s)
          AND c.relkind IN ('v','m')
        ORDER BY n.nspname, c.relname
        """,
        True,
    ),
    QuerySpec(
        "catalog.triggers",
        """
        SELECT
            t.oid,
            n.nspname AS schema_name,
            c.relname AS relation_name,
            t.tgname AS trigger_name,
            t.tgenabled,
            pg_catalog.pg_get_triggerdef(t.oid, true) AS definition
        FROM pg_catalog.pg_trigger t
        JOIN pg_catalog.pg_class c ON c.oid = t.tgrelid
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = ANY(%s)
          AND NOT t.tgisinternal
        ORDER BY n.nspname, c.relname, t.tgname
        """,
        True,
    ),
    QuerySpec(
        "catalog.rls",
        """
        SELECT
            p.oid,
            n.nspname AS schema_name,
            c.relname AS relation_name,
            p.polname AS policy_name,
            p.polpermissive,
            p.polcmd,
            COALESCE((
                SELECT pg_catalog.array_agg(r.rolname ORDER BY r.rolname)
                FROM pg_catalog.unnest(p.polroles) AS x(role_oid)
                JOIN pg_catalog.pg_roles r ON r.oid = x.role_oid
            ), ARRAY[]::name[]) AS roles,
            CASE WHEN p.polqual IS NULL THEN NULL
                 ELSE pg_catalog.pg_get_expr(p.polqual, p.polrelid) END AS using_expression,
            CASE WHEN p.polwithcheck IS NULL THEN NULL
                 ELSE pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid) END AS with_check_expression
        FROM pg_catalog.pg_policy p
        JOIN pg_catalog.pg_class c ON c.oid = p.polrelid
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = ANY(%s)
        ORDER BY n.nspname, c.relname, p.polname
        """,
        True,
    ),
    QuerySpec(
        "catalog.extensions",
        """
        SELECT
            e.oid,
            e.extname AS extension_name,
            e.extversion AS extension_version,
            n.nspname AS schema_name,
            r.rolname AS owner_name
        FROM pg_catalog.pg_extension e
        JOIN pg_catalog.pg_namespace n ON n.oid = e.extnamespace
        JOIN pg_catalog.pg_roles r ON r.oid = e.extowner
        ORDER BY e.extname
        """,
    ),
    QuerySpec(
        "security.roles",
        """
        SELECT
            oid,
            rolname,
            rolcanlogin,
            rolsuper,
            rolinherit,
            rolcreaterole,
            rolcreatedb,
            rolreplication,
            rolbypassrls
        FROM pg_catalog.pg_roles
        ORDER BY rolname
        """,
    ),
    QuerySpec(
        "security.memberships",
        """
        SELECT
            member.rolname AS member_role,
            granted.rolname AS granted_role,
            grantor.rolname AS grantor_role,
            m.admin_option,
            m.inherit_option,
            m.set_option
        FROM pg_catalog.pg_auth_members m
        JOIN pg_catalog.pg_roles member ON member.oid = m.member
        JOIN pg_catalog.pg_roles granted ON granted.oid = m.roleid
        JOIN pg_catalog.pg_roles grantor ON grantor.oid = m.grantor
        ORDER BY member.rolname, granted.rolname, grantor.rolname
        """,
    ),
    QuerySpec(
        "security.database_acl",
        """
        SELECT
            d.datname AS database_name,
            owner.rolname AS owner_name,
            CASE WHEN x.grantee = 0 THEN 'PUBLIC' ELSE grantee.rolname END AS grantee,
            x.privilege_type,
            x.is_grantable
        FROM pg_catalog.pg_database d
        JOIN pg_catalog.pg_roles owner ON owner.oid = d.datdba
        CROSS JOIN LATERAL pg_catalog.aclexplode(
            COALESCE(d.datacl, pg_catalog.acldefault('d', d.datdba))
        ) AS x
        LEFT JOIN pg_catalog.pg_roles grantee ON grantee.oid = x.grantee
        WHERE d.datname = pg_catalog.current_database()
        ORDER BY grantee, x.privilege_type
        """,
    ),
    QuerySpec(
        "security.schema_acls",
        """
        SELECT
            n.nspname AS schema_name,
            owner.rolname AS owner_name,
            CASE WHEN x.grantee = 0 THEN 'PUBLIC' ELSE grantee.rolname END AS grantee,
            x.privilege_type,
            x.is_grantable
        FROM pg_catalog.pg_namespace n
        JOIN pg_catalog.pg_roles owner ON owner.oid = n.nspowner
        CROSS JOIN LATERAL pg_catalog.aclexplode(
            COALESCE(n.nspacl, pg_catalog.acldefault('n', n.nspowner))
        ) AS x
        LEFT JOIN pg_catalog.pg_roles grantee ON grantee.oid = x.grantee
        WHERE n.nspname = ANY(%s)
        ORDER BY n.nspname, grantee, x.privilege_type
        """,
        True,
    ),
    QuerySpec(
        "security.relation_acls",
        """
        SELECT
            n.nspname AS schema_name,
            c.relname AS relation_name,
            c.relkind,
            owner.rolname AS owner_name,
            CASE WHEN x.grantee = 0 THEN 'PUBLIC' ELSE grantee.rolname END AS grantee,
            x.privilege_type,
            x.is_grantable
        FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        JOIN pg_catalog.pg_roles owner ON owner.oid = c.relowner
        CROSS JOIN LATERAL pg_catalog.aclexplode(
            COALESCE(
                c.relacl,
                pg_catalog.acldefault(
                    CASE WHEN c.relkind = 'S' THEN 'S'::"char" ELSE 'r'::"char" END,
                    c.relowner
                )
            )
        ) AS x
        LEFT JOIN pg_catalog.pg_roles grantee ON grantee.oid = x.grantee
        WHERE n.nspname = ANY(%s)
          AND c.relkind IN ('r','p','v','m','S','f')
        ORDER BY n.nspname, c.relname, grantee, x.privilege_type
        """,
        True,
    ),
    QuerySpec(
        "security.function_acls",
        """
        SELECT
            n.nspname AS schema_name,
            p.proname AS function_name,
            pg_catalog.pg_get_function_identity_arguments(p.oid) AS identity_arguments,
            owner.rolname AS owner_name,
            CASE WHEN x.grantee = 0 THEN 'PUBLIC' ELSE grantee.rolname END AS grantee,
            x.privilege_type,
            x.is_grantable
        FROM pg_catalog.pg_proc p
        JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
        JOIN pg_catalog.pg_roles owner ON owner.oid = p.proowner
        CROSS JOIN LATERAL pg_catalog.aclexplode(
            COALESCE(p.proacl, pg_catalog.acldefault('f', p.proowner))
        ) AS x
        LEFT JOIN pg_catalog.pg_roles grantee ON grantee.oid = x.grantee
        WHERE n.nspname = ANY(%s)
        ORDER BY n.nspname, p.proname, identity_arguments, grantee, x.privilege_type
        """,
        True,
    ),
    QuerySpec(
        "security.default_acls",
        """
        SELECT
            owner.rolname AS owner_name,
            COALESCE(n.nspname, '*') AS schema_name,
            d.defaclobjtype,
            CASE WHEN x.grantee = 0 THEN 'PUBLIC' ELSE grantee.rolname END AS grantee,
            x.privilege_type,
            x.is_grantable
        FROM pg_catalog.pg_default_acl d
        JOIN pg_catalog.pg_roles owner ON owner.oid = d.defaclrole
        LEFT JOIN pg_catalog.pg_namespace n ON n.oid = d.defaclnamespace
        CROSS JOIN LATERAL pg_catalog.aclexplode(d.defaclacl) AS x
        LEFT JOIN pg_catalog.pg_roles grantee ON grantee.oid = x.grantee
        WHERE d.defaclnamespace = 0 OR n.nspname = ANY(%s)
        ORDER BY owner.rolname, schema_name, d.defaclobjtype, grantee, x.privilege_type
        """,
        True,
    ),
    QuerySpec(
        "migration.alembic_revision",
        "SELECT version_num FROM public.alembic_version ORDER BY version_num",
    ),
)

QUERY_BY_NAME = {spec.name: spec for spec in QUERY_SPECS}
REQUIRED_CATALOG_SURFACES = tuple(spec.name for spec in QUERY_SPECS)
QUERY_PACK_SHA256 = sha256_canonical(
    {
        "version": QUERY_PACK_VERSION,
        "queries": [
            {
                "name": spec.name,
                "namespace_scoped": spec.namespace_scoped,
                "sql": " ".join(spec.sql.split()),
            }
            for spec in QUERY_SPECS
        ],
    }
)


def get_query(name: str) -> QuerySpec:
    try:
        return QUERY_BY_NAME[name]
    except KeyError as exc:
        raise KeyError(f"unknown fixed query: {name}") from exc
