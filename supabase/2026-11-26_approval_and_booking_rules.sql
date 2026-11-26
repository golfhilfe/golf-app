-- 1) Approval of new sign-ups + blocking
alter table public.profiles add column if not exists approved boolean not null default false,
  add column if not exists declined boolean not null default false;
update public.profiles set approved = true where not approved and not declined;

create or replace function public.is_approved() returns boolean
language sql stable security definer set search_path to '' as $$
  select coalesce((select (approved and not declined) or role = 'coach' from public.profiles where id = auth.uid()), false)
$$;

-- Clients may edit their own profile, but never their role, academy, approval or block.
create or replace function public.guard_profile() returns trigger
language plpgsql security definer set search_path to '' as $$
begin
  if auth.uid() is not null and not public.is_coach() then
    new.role := old.role; new.academy_id := old.academy_id;
    new.approved := old.approved; new.declined := old.declined;
  end if;
  return new;
end $$;
drop trigger if exists guard_profile on public.profiles;
create trigger guard_profile before update on public.profiles for each row execute function public.guard_profile();

drop policy if exists "approved only" on public.bookings;
drop policy if exists "approved only" on public.camp_registrations;
drop policy if exists "approved only" on public.assigned_drills;
create policy "approved only" on public.bookings as restrictive for insert to authenticated with check ((select public.is_approved()));
create policy "approved only" on public.camp_registrations as restrictive for insert to authenticated with check ((select public.is_approved()));
create policy "approved only" on public.assigned_drills as restrictive for insert to authenticated with check ((select public.is_approved()));

create or replace function public.join_group(p_session uuid)
 returns boolean language plpgsql security definer set search_path to '' as $function$
declare cap int; n int; wl boolean;
begin
  if not public.is_approved() then raise exception 'not approved'; end if;
  select capacity into cap from public.group_sessions where id = p_session and academy_id = public.my_academy() for update;
  if cap is null then raise exception 'not found'; end if;
  select count(*) into n from public.group_signups where session_id = p_session and not waitlist;
  wl := n >= cap;
  insert into public.group_signups(session_id, client_id, waitlist) values (p_session, auth.uid(), wl)
  on conflict do nothing;
  return wl;
end $function$;

-- Coach blocks or unblocks a student. Blocking cancels their upcoming lessons and sign-ups.
create or replace function public.set_client_blocked(p_client uuid, p_block boolean)
 returns void language plpgsql security definer set search_path to '' as $$
begin
  if not public.is_coach() then raise exception 'coach only'; end if;
  update public.profiles set declined = p_block, approved = not p_block
   where id = p_client and role = 'client' and academy_id = public.my_academy();
  if p_block then
    update public.bookings set status = 'cancelled' where client_id = p_client and status = 'booked' and starts_at > now();
    delete from public.group_signups s using public.group_sessions g where s.session_id = g.id and s.client_id = p_client and g.starts_at > now();
    delete from public.camp_registrations r using public.camps c where r.camp_id = c.id and r.client_id = p_client and c.start_date > current_date;
  end if;
end $$;

-- 2) Booking rules for students: max 3 weeks ahead, max 3 hours per week (Mon-Sun, Berlin time),
--    students may only cancel (not move) a booking, and only up to 24 hours before.
create or replace function public.check_booking_rules() returns trigger
language plpgsql security definer set search_path to '' as $$
declare wk timestamptz; used int; m int;
begin
  if auth.uid() is null or public.is_coach() then return new; end if;
  if tg_op = 'UPDATE' then
    if new.status = 'cancelled' and old.status = 'booked' and old.starts_at > now() + interval '24 hours' then
      new.starts_at := old.starts_at; new.lesson_type_id := old.lesson_type_id; new.client_id := old.client_id; new.academy_id := old.academy_id;
      return new;
    end if;
    raise exception 'BOOK_NO_CHANGE';
  end if;
  if new.starts_at > now() + interval '21 days' then raise exception 'BOOK_TOO_FAR'; end if;
  wk := date_trunc('week', new.starts_at at time zone 'Europe/Berlin') at time zone 'Europe/Berlin';
  select coalesce(sum(lt.minutes), 0) into used from public.bookings b join public.lesson_types lt on lt.id = b.lesson_type_id
   where b.client_id = new.client_id and b.status = 'booked' and b.starts_at >= wk and b.starts_at < wk + interval '7 days';
  select minutes into m from public.lesson_types where id = new.lesson_type_id;
  if used + coalesce(m, 0) > 180 then raise exception 'BOOK_WEEK_LIMIT'; end if;
  return new;
end $$;
drop trigger if exists booking_rules on public.bookings;
create trigger booking_rules before insert or update on public.bookings for each row execute function public.check_booking_rules();

revoke execute on function public.is_approved() from anon;
revoke execute on function public.set_client_blocked(uuid, boolean) from anon;
revoke execute on function public.guard_profile() from anon, authenticated;
revoke execute on function public.check_booking_rules() from anon, authenticated;
