-- Ebelu Aktuell secure publication backend
create table if not exists public.ebelu_admins (user_id uuid primary key references auth.users(id) on delete cascade, created_at timestamptz not null default now());
create table if not exists public.ebelu_issues (id uuid primary key default gen_random_uuid(), title text not null check(char_length(title) between 2 and 120), edition_number integer not null unique check(edition_number>0), description text not null default '' check(char_length(description)<=1000), file_path text not null unique, code_hash text not null unique, published boolean not null default false, created_at timestamptz not null default now());
create table if not exists public.ebelu_vouchers (id uuid primary key default gen_random_uuid(), code_hash text not null unique, redeemed_at timestamptz, redeemed_by text, created_at timestamptz not null default now());
create table if not exists public.ebelu_rate_limits (key_hash text primary key, window_started_at timestamptz not null default now(), attempts integer not null default 0);
create table if not exists public.ebelu_audit_log (id bigint generated always as identity primary key, actor uuid, action text not null, target_id uuid, created_at timestamptz not null default now());
alter table public.ebelu_admins enable row level security;
alter table public.ebelu_issues enable row level security;
alter table public.ebelu_vouchers enable row level security;
alter table public.ebelu_rate_limits enable row level security;
alter table public.ebelu_audit_log enable row level security;
revoke all on public.ebelu_admins,public.ebelu_issues,public.ebelu_vouchers,public.ebelu_rate_limits,public.ebelu_audit_log from anon,authenticated,public;
grant all on public.ebelu_admins,public.ebelu_issues,public.ebelu_vouchers,public.ebelu_rate_limits,public.ebelu_audit_log to service_role;
insert into storage.buckets(id,name,public,file_size_limit,allowed_mime_types) values('ebelu-issues','ebelu-issues',false,15728640,array['application/pdf']) on conflict(id) do update set public=false,file_size_limit=15728640,allowed_mime_types=array['application/pdf'];
create or replace function public.ebelu_consume_rate_limit(p_key_hash text) returns boolean language plpgsql security definer set search_path='' as $$ declare v_attempts integer; begin insert into public.ebelu_rate_limits(key_hash,window_started_at,attempts) values(p_key_hash,now(),1) on conflict(key_hash) do update set attempts=case when public.ebelu_rate_limits.window_started_at<now()-interval '15 minutes' then 1 else public.ebelu_rate_limits.attempts+1 end,window_started_at=case when public.ebelu_rate_limits.window_started_at<now()-interval '15 minutes' then now() else public.ebelu_rate_limits.window_started_at end returning attempts into v_attempts; return v_attempts<=5; end; $$;
revoke all on function public.ebelu_consume_rate_limit(text) from public,anon,authenticated;
grant execute on function public.ebelu_consume_rate_limit(text) to service_role;
