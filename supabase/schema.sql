-- =====================================================================
-- MEP,SFA シフト作成ツール  データベース定義
--   Supabase の SQL Editor に全文を貼り付けて「Run」してください。
--   何度実行しても壊れないように書いてあります（作り直しではなく上書き）。
-- =====================================================================

create extension if not exists pgcrypto with schema extensions;

-- ---------------------------------------------------------------------
-- テーブル
-- ---------------------------------------------------------------------
create table if not exists public.app_global (
  key        text primary key,
  value      jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now()
);

create table if not exists public.stores (
  id            uuid primary key default gen_random_uuid(),
  code          text not null unique,
  name          text not null,
  manager_hash  text not null,
  staff_hash    text not null,
  settings      jsonb not null default '{}'::jsonb,
  fail_count    int not null default 0,
  locked_until  timestamptz,
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now()
);

create table if not exists public.months (
  store_id   uuid not null references public.stores(id) on delete cascade,
  ym         text not null check (ym ~ '^\d{4}-\d{2}$'),
  doc        jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now(),
  primary key (store_id, ym)
);

create table if not exists public.wishes (
  store_id   uuid not null,
  ym         text not null,
  staff_id   text not null,
  data       jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now(),
  primary key (store_id, ym, staff_id),
  foreign key (store_id, ym) references public.months(store_id, ym) on delete cascade
);

create table if not exists public.sessions (
  token      uuid primary key default gen_random_uuid(),
  role       text not null check (role in ('admin','manager','staff')),
  store_id   uuid references public.stores(id) on delete cascade,
  expires_at timestamptz not null
);

-- 社員はパスワードなしで入れる（店長が設定で切り替え）
alter table public.stores add column if not exists staff_open boolean not null default true;

-- ブラウザから直接テーブルを読み書きさせない（下の関数経由のみ）
alter table public.app_global enable row level security;
alter table public.stores     enable row level security;
alter table public.months     enable row level security;
alter table public.wishes     enable row level security;
alter table public.sessions   enable row level security;
revoke all on public.app_global, public.stores, public.months, public.wishes, public.sessions from anon, authenticated;

-- ---------------------------------------------------------------------
-- 内部ヘルパー
-- ---------------------------------------------------------------------
create or replace function public._hash(p text) returns text
language sql volatile set search_path = public, extensions as $$
  select extensions.crypt(p, extensions.gen_salt('bf', 8));
$$;

create or replace function public._check(p text, h text) returns boolean
language sql stable set search_path = public, extensions as $$
  select h is not null and extensions.crypt(p, h) = h;
$$;

create or replace function public._new_session(p_role text, p_store uuid) returns uuid
language plpgsql volatile set search_path = public, extensions as $$
declare t uuid;
begin
  delete from sessions where expires_at < now();
  insert into sessions(role, store_id, expires_at)
  values (p_role, p_store, now() + interval '30 days') returning token into t;
  return t;
end $$;

-- セッション確認。p_need: 'admin' | 'manager' | 'store'(店長か社員) | 'any'
create or replace function public._auth(p_token uuid, p_need text, out o_role text, out o_store uuid)
language plpgsql volatile set search_path = public, extensions as $$
begin
  select role, store_id into o_role, o_store from sessions
   where token = p_token and expires_at > now();
  if o_role is null then raise exception 'AUTH' using hint = 'ログインし直してください'; end if;
  update sessions set expires_at = now() + interval '30 days' where token = p_token;
  if p_need = 'admin' and o_role <> 'admin' then raise exception 'FORBIDDEN'; end if;
  if p_need = 'manager' and o_role <> 'manager' then raise exception 'FORBIDDEN'; end if;
  if p_need = 'store' and o_role not in ('manager','staff') then raise exception 'FORBIDDEN'; end if;
end $$;

create or replace function public._valid_code(p text) returns boolean
language sql immutable as $$ select p ~ '^[a-z0-9][a-z0-9-]{1,39}$' $$;

-- ---------------------------------------------------------------------
-- 全体管理者
-- ---------------------------------------------------------------------
create or replace function public.admin_status() returns jsonb
language sql stable security definer set search_path = public, extensions as $$
  select jsonb_build_object('configured', exists(select 1 from app_global where key = 'admin'));
$$;

-- 初回だけ使える：管理者パスワードの設定
create or replace function public.admin_setup(p_password text) returns jsonb
language plpgsql volatile security definer set search_path = public, extensions as $$
begin
  if exists(select 1 from app_global where key = 'admin') then
    return jsonb_build_object('ok', false, 'error', 'ALREADY');
  end if;
  if length(coalesce(p_password,'')) < 8 then
    return jsonb_build_object('ok', false, 'error', 'WEAK');
  end if;
  insert into app_global(key, value) values ('admin', jsonb_build_object('hash', _hash(p_password), 'fail', 0));
  return jsonb_build_object('ok', true, 'token', _new_session('admin', null));
end $$;

create or replace function public.admin_login(p_password text) returns jsonb
language plpgsql volatile security definer set search_path = public, extensions as $$
declare v jsonb;
begin
  select value into v from app_global where key = 'admin';
  if v is null then return jsonb_build_object('ok', false, 'error', 'NOT_CONFIGURED'); end if;
  if (v->>'locked_until') is not null and (v->>'locked_until')::timestamptz > now() then
    return jsonb_build_object('ok', false, 'error', 'LOCKED');
  end if;
  if not _check(p_password, v->>'hash') then
    update app_global set value = case when coalesce((v->>'fail')::int,0) + 1 >= 10
        then (v - 'fail') || jsonb_build_object('fail', 0, 'locked_until', now() + interval '10 minutes')
        else v || jsonb_build_object('fail', coalesce((v->>'fail')::int,0) + 1) end
     where key = 'admin';
    return jsonb_build_object('ok', false, 'error', 'BAD_PASSWORD');
  end if;
  update app_global set value = (v - 'locked_until') || jsonb_build_object('fail', 0) where key = 'admin';
  return jsonb_build_object('ok', true, 'token', _new_session('admin', null), 'role', 'admin');
end $$;

create or replace function public.admin_set_password(p_token uuid, p_new text) returns jsonb
language plpgsql volatile security definer set search_path = public, extensions as $$
begin
  perform _auth(p_token, 'admin');
  if length(coalesce(p_new,'')) < 8 then raise exception 'WEAK'; end if;
  update app_global set value = jsonb_build_object('hash', _hash(p_new), 'fail', 0) where key = 'admin';
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.admin_list_stores(p_token uuid) returns jsonb
language plpgsql volatile security definer set search_path = public, extensions as $$
begin
  perform _auth(p_token, 'admin');
  return coalesce((select jsonb_agg(jsonb_build_object('code', code, 'name', name, 'created_at', created_at) order by created_at)
                     from stores), '[]'::jsonb);
end $$;

create or replace function public.admin_create_store(p_token uuid, p_code text, p_name text, p_manager_pw text, p_staff_pw text) returns jsonb
language plpgsql volatile security definer set search_path = public, extensions as $$
begin
  perform _auth(p_token, 'admin');
  p_code := lower(trim(p_code));
  if not _valid_code(p_code) then raise exception 'BAD_CODE'; end if;
  if length(trim(coalesce(p_name,''))) = 0 then raise exception 'BAD_NAME'; end if;
  if length(coalesce(p_manager_pw,'')) < 6 then raise exception 'WEAK'; end if;
  if coalesce(p_staff_pw,'') <> '' and length(p_staff_pw) < 4 then raise exception 'WEAK'; end if;
  if p_manager_pw = p_staff_pw then raise exception 'SAME_PASSWORD'; end if;
  if exists(select 1 from stores where code = p_code) then raise exception 'DUPLICATE'; end if;
  insert into stores(code, name, manager_hash, staff_hash, staff_open)
  values (p_code, trim(p_name), _hash(p_manager_pw), _hash(coalesce(nullif(p_staff_pw,''), gen_random_uuid()::text)),
          coalesce(p_staff_pw,'') = '');
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.admin_update_store(p_token uuid, p_code text, p_name text, p_manager_pw text, p_staff_pw text) returns jsonb
language plpgsql volatile security definer set search_path = public, extensions as $$
declare s stores;
begin
  perform _auth(p_token, 'admin');
  select * into s from stores where code = lower(trim(p_code));
  if s.id is null then raise exception 'NOT_FOUND'; end if;
  if coalesce(p_manager_pw,'') <> '' and length(p_manager_pw) < 6 then raise exception 'WEAK'; end if;
  if coalesce(p_staff_pw,'') <> '' and length(p_staff_pw) < 4 then raise exception 'WEAK'; end if;
  update stores set
    name = coalesce(nullif(trim(p_name),''), name),
    manager_hash = case when coalesce(p_manager_pw,'') <> '' then _hash(p_manager_pw) else manager_hash end,
    staff_hash   = case when coalesce(p_staff_pw,'')   <> '' then _hash(p_staff_pw)   else staff_hash end,
    fail_count = 0, locked_until = null, updated_at = now()
  where id = s.id;
  if coalesce(p_manager_pw,'') <> '' or coalesce(p_staff_pw,'') <> '' then
    delete from sessions where store_id = s.id;
  end if;
  return jsonb_build_object('ok', true);
end $$;

-- 全店共通データ（calendar：月ごとの休日数・祝日 / notice：お知らせ）
create or replace function public.admin_save_global(p_token uuid, p_key text, p_value jsonb) returns jsonb
language plpgsql volatile security definer set search_path = public, extensions as $$
begin
  perform _auth(p_token, 'admin');
  if p_key not in ('calendar', 'notice') then raise exception 'BAD_KEY'; end if;
  insert into app_global(key, value, updated_at) values (p_key, coalesce(p_value, '{}'::jsonb), now())
  on conflict (key) do update set value = excluded.value, updated_at = now();
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.get_global(p_token uuid) returns jsonb
language plpgsql volatile security definer set search_path = public, extensions as $$
begin
  perform _auth(p_token, 'any');
  return jsonb_build_object(
    'calendar', coalesce((select value from app_global where key = 'calendar'), '{}'::jsonb),
    'notice',   coalesce((select value from app_global where key = 'notice'), '{}'::jsonb));
end $$;

-- ---------------------------------------------------------------------
-- 店舗ログイン（店長 or 社員）
-- ---------------------------------------------------------------------
create or replace function public.store_login(p_code text, p_password text) returns jsonb
language plpgsql volatile security definer set search_path = public, extensions as $$
declare s stores; r text;
begin
  select * into s from stores where code = lower(trim(p_code));
  if s.id is null then return jsonb_build_object('ok', false, 'error', 'BAD_LOGIN'); end if;
  if s.locked_until is not null and s.locked_until > now() then
    return jsonb_build_object('ok', false, 'error', 'LOCKED');
  end if;
  if _check(p_password, s.manager_hash) then r := 'manager';
  elsif _check(p_password, s.staff_hash) then r := 'staff';
  end if;
  if r is null then
    update stores set
      fail_count = case when fail_count + 1 >= 10 then 0 else fail_count + 1 end,
      locked_until = case when fail_count + 1 >= 10 then now() + interval '10 minutes' else locked_until end
    where id = s.id;
    return jsonb_build_object('ok', false, 'error', 'BAD_LOGIN');
  end if;
  update stores set fail_count = 0, locked_until = null where id = s.id;
  return jsonb_build_object('ok', true, 'token', _new_session(r, s.id), 'role', r,
                            'store', jsonb_build_object('code', s.code, 'name', s.name));
end $$;

create or replace function public.store_lookup(p_code text) returns jsonb
language plpgsql stable security definer set search_path = public, extensions as $$
declare s stores;
begin
  select * into s from stores where code = lower(trim(p_code));
  if s.id is null then return jsonb_build_object('ok', false, 'error', 'NO_STORE'); end if;
  return jsonb_build_object('ok', true, 'code', s.code, 'name', s.name, 'staffOpen', s.staff_open);
end $$;

create or replace function public.store_login_staff(p_code text) returns jsonb
language plpgsql volatile security definer set search_path = public, extensions as $$
declare s stores;
begin
  select * into s from stores where code = lower(trim(p_code));
  if s.id is null then return jsonb_build_object('ok', false, 'error', 'NO_STORE'); end if;
  if not s.staff_open then return jsonb_build_object('ok', false, 'error', 'NEED_PASSWORD'); end if;
  return jsonb_build_object('ok', true, 'token', _new_session('staff', s.id), 'role', 'staff',
                            'store', jsonb_build_object('code', s.code, 'name', s.name));
end $$;

create or replace function public.set_staff_open(p_token uuid, p_open boolean) returns jsonb
language plpgsql volatile security definer set search_path = public, extensions as $$
declare a record;
begin
  select * into a from _auth(p_token, 'manager');
  update stores set staff_open = coalesce(p_open, true), updated_at = now() where id = a.o_store;
  return jsonb_build_object('ok', true);
end $$;

-- みんなの希望（休み希望などの日付だけ。メモは店長だけが見られる）
create or replace function public.get_wish_board(p_token uuid, p_ym text) returns jsonb
language plpgsql volatile security definer set search_path = public, extensions as $$
declare a record;
begin
  select * into a from _auth(p_token, 'store');
  return coalesce((select jsonb_object_agg(staff_id, coalesce(data->'days', '{}'::jsonb))
                     from wishes where store_id = a.o_store and ym = p_ym), '{}'::jsonb);
end $$;

create or replace function public.logout(p_token uuid) returns jsonb
language sql volatile security definer set search_path = public, extensions as $$
  delete from sessions where token = p_token;
  select jsonb_build_object('ok', true);
$$;

create or replace function public.whoami(p_token uuid) returns jsonb
language plpgsql volatile security definer set search_path = public, extensions as $$
declare a record; s stores;
begin
  select * into a from _auth(p_token, 'any');
  if a.o_store is not null then select * into s from stores where id = a.o_store; end if;
  return jsonb_build_object('role', a.o_role,
    'store', case when s.id is null then null else jsonb_build_object('code', s.code, 'name', s.name) end);
end $$;

-- ---------------------------------------------------------------------
-- 店舗設定
-- ---------------------------------------------------------------------
create or replace function public.get_store(p_token uuid) returns jsonb
language plpgsql volatile security definer set search_path = public, extensions as $$
declare a record; s stores;
begin
  select * into a from _auth(p_token, 'store');
  select * into s from stores where id = a.o_store;
  return jsonb_build_object('code', s.code, 'name', s.name, 'settings', s.settings, 'updated_at', s.updated_at, 'staffOpen', s.staff_open);
end $$;

create or replace function public.save_store_settings(p_token uuid, p_settings jsonb) returns jsonb
language plpgsql volatile security definer set search_path = public, extensions as $$
declare a record;
begin
  select * into a from _auth(p_token, 'manager');
  if jsonb_typeof(p_settings) <> 'object' then raise exception 'BAD_SETTINGS'; end if;
  update stores set settings = p_settings, updated_at = now() where id = a.o_store;
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.change_store_password(p_token uuid, p_which text, p_new text) returns jsonb
language plpgsql volatile security definer set search_path = public, extensions as $$
declare a record; s stores;
begin
  select * into a from _auth(p_token, 'manager');
  select * into s from stores where id = a.o_store;
  if p_which = 'manager' then
    if length(coalesce(p_new,'')) < 6 then raise exception 'WEAK'; end if;
    if _check(p_new, s.staff_hash) then raise exception 'SAME_PASSWORD'; end if;
    update stores set manager_hash = _hash(p_new), updated_at = now() where id = s.id;
    delete from sessions where store_id = s.id and role = 'manager' and token <> p_token;
  elsif p_which = 'staff' then
    if length(coalesce(p_new,'')) < 4 then raise exception 'WEAK'; end if;
    if _check(p_new, s.manager_hash) then raise exception 'SAME_PASSWORD'; end if;
    update stores set staff_hash = _hash(p_new), updated_at = now() where id = s.id;
    delete from sessions where store_id = s.id and role = 'staff';
  else
    raise exception 'BAD_KIND';
  end if;
  return jsonb_build_object('ok', true);
end $$;

-- ---------------------------------------------------------------------
-- 月（シフト表）と希望
-- ---------------------------------------------------------------------
create or replace function public.list_months(p_token uuid) returns jsonb
language plpgsql volatile security definer set search_path = public, extensions as $$
declare a record;
begin
  select * into a from _auth(p_token, 'store');
  return coalesce((select jsonb_agg(jsonb_build_object(
            'ym', ym, 'status', coalesce(doc->>'status','collecting'), 'deadline', doc->>'deadline',
            'updated_at', updated_at) order by ym desc)
          from months where store_id = a.o_store), '[]'::jsonb);
end $$;

-- 店長：表の全部＋全員の希望 / 社員：締切・状態と、確定後のシフトのみ
create or replace function public.get_month(p_token uuid, p_ym text) returns jsonb
language plpgsql volatile security definer set search_path = public, extensions as $$
declare a record; m months;
begin
  select * into a from _auth(p_token, 'store');
  select * into m from months where store_id = a.o_store and ym = p_ym;
  if m.store_id is null then return null; end if;
  if a.o_role = 'manager' then
    return jsonb_build_object('ym', m.ym, 'doc', m.doc, 'updated_at', m.updated_at,
      'wishes', coalesce((select jsonb_object_agg(staff_id, jsonb_build_object('data', data, 'updated_at', updated_at))
                            from wishes where store_id = a.o_store and ym = p_ym), '{}'::jsonb));
  end if;
  return jsonb_build_object('ym', m.ym, 'updated_at', m.updated_at, 'doc', jsonb_build_object(
    'status', coalesce(m.doc->>'status','collecting'),
    'deadline', m.doc->'deadline',
    'message', m.doc->'message',
    'overrides', m.doc->'overrides',
    'final', case when m.doc->>'status' = 'final' then m.doc->'final' else null end));
end $$;

create or replace function public.save_month(p_token uuid, p_ym text, p_doc jsonb, p_expected timestamptz default null) returns jsonb
language plpgsql volatile security definer set search_path = public, extensions as $$
declare a record; cur timestamptz; t timestamptz;
begin
  select * into a from _auth(p_token, 'manager');
  if p_ym !~ '^\d{4}-\d{2}$' then raise exception 'BAD_MONTH'; end if;
  select updated_at into cur from months where store_id = a.o_store and ym = p_ym;
  if p_expected is not null and cur is not null and cur > p_expected + interval '1 millisecond' then
    raise exception 'CONFLICT' using hint = '別の端末で更新されています。読み込み直してください';
  end if;
  insert into months(store_id, ym, doc, updated_at) values (a.o_store, p_ym, coalesce(p_doc,'{}'::jsonb), now())
  on conflict (store_id, ym) do update set doc = excluded.doc, updated_at = now()
  returning updated_at into t;
  return jsonb_build_object('ok', true, 'updated_at', t);
end $$;

create or replace function public.delete_month(p_token uuid, p_ym text) returns jsonb
language plpgsql volatile security definer set search_path = public, extensions as $$
declare a record;
begin
  select * into a from _auth(p_token, 'manager');
  delete from months where store_id = a.o_store and ym = p_ym;
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.get_wish(p_token uuid, p_ym text, p_staff_id text) returns jsonb
language plpgsql volatile security definer set search_path = public, extensions as $$
declare a record;
begin
  select * into a from _auth(p_token, 'store');
  return (select jsonb_build_object('data', data, 'updated_at', updated_at) from wishes
           where store_id = a.o_store and ym = p_ym and staff_id = p_staff_id);
end $$;

create or replace function public.save_wish(p_token uuid, p_ym text, p_staff_id text, p_data jsonb) returns jsonb
language plpgsql volatile security definer set search_path = public, extensions as $$
declare a record; m months; s stores; dl date;
begin
  select * into a from _auth(p_token, 'store');
  select * into m from months where store_id = a.o_store and ym = p_ym;
  if m.store_id is null then raise exception 'NO_MONTH'; end if;
  select * into s from stores where id = a.o_store;
  if not exists (select 1 from jsonb_array_elements(coalesce(s.settings->'staff','[]'::jsonb)) e where e->>'id' = p_staff_id) then
    raise exception 'NO_STAFF';
  end if;
  if a.o_role = 'staff' then
    if coalesce(m.doc->>'status','collecting') <> 'collecting' then raise exception 'CLOSED'; end if;
    dl := nullif(m.doc->>'deadline','')::date;
    if dl is not null and (now() at time zone 'Asia/Tokyo')::date > dl then raise exception 'CLOSED'; end if;
  end if;
  if jsonb_typeof(p_data) <> 'object' then raise exception 'BAD_DATA'; end if;
  insert into wishes(store_id, ym, staff_id, data, updated_at) values (a.o_store, p_ym, p_staff_id, p_data, now())
  on conflict (store_id, ym, staff_id) do update set data = excluded.data, updated_at = now();
  return jsonb_build_object('ok', true);
end $$;

-- ---------------------------------------------------------------------
-- 公開する関数（ブラウザから呼べるのはこれだけ）
-- ---------------------------------------------------------------------
revoke execute on all functions in schema public from public, anon, authenticated;
grant execute on function
  public.admin_status(), public.admin_setup(text), public.admin_login(text),
  public.admin_set_password(uuid, text), public.admin_list_stores(uuid),
  public.admin_create_store(uuid, text, text, text, text), public.admin_update_store(uuid, text, text, text, text),
  public.admin_save_global(uuid, text, jsonb), public.get_global(uuid),
  public.store_login(text, text), public.logout(uuid), public.whoami(uuid),
  public.store_lookup(text), public.store_login_staff(text), public.set_staff_open(uuid, boolean),
  public.get_wish_board(uuid, text),
  public.get_store(uuid), public.save_store_settings(uuid, jsonb), public.change_store_password(uuid, text, text),
  public.list_months(uuid), public.get_month(uuid, text), public.save_month(uuid, text, jsonb, timestamptz),
  public.delete_month(uuid, text), public.get_wish(uuid, text, text), public.save_wish(uuid, text, text, jsonb)
to anon, authenticated;

notify pgrst, 'reload schema';
