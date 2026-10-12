# GIS dashboard v2 (pre-configured for database gisdb, table public.plsd)

## 0. Stop the old stack (in the OLD folder)
    docker compose down --remove-orphans

## 1. One-time: let Docker reach your Windows PostgreSQL
1. pgAdmin Query Tool: `SHOW hba_file;` and `SHOW config_file;`
2. Open pg_hba.conf in Notepad **as Administrator**, add at the bottom:
       host  all  all  172.16.0.0/12   scram-sha-256
       host  all  all  192.168.0.0/16  scram-sha-256
   (use md5 instead of scram-sha-256 on PostgreSQL 13 or older)
3. In postgresql.conf set: listen_addresses = '*'
4. Win+R -> services.msc -> restart the postgresql-x64-... service
5. Admin PowerShell:
       New-NetFirewallRule -DisplayName "PostgreSQL" -Direction Inbound -Protocol TCP -LocalPort 5432 -Action Allow
   (local testing only; on a real server restrict who can reach 5432)

## 2. Start (from this folder)
    docker compose up -d --build
    docker compose ps

## 3. Check, in this order
- http://localhost/api/health/db   -> {"database":"ok"}
- http://localhost/tiles/public.plsd.json -> JSON (bounds, fields)
- http://localhost/   -> map + login

If something fails: `docker compose logs backend --tail 30`.
After fixing DB access: `docker compose restart backend`.

## Notes
- .env holds your DB password and admin login. Change both before real deployment, keep it out of shared folders.
- /tiles and /features are protected by the Nginx authentication check, which validates the user token and applies the configured layer-access policy. Review and test role permissions before deployment.
