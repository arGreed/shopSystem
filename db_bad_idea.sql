
--? Функция хеширования.
create or replace function generate_hash(
	p_words	text[]
)
returns uuid 
as $$
begin
	--? Конвертация аттрибутов в уникальный хеш.
	return md5(trim(upper(array_to_string(p_words,''))))::uuid;
end
$$ language plpgsql;
--? Лишение всех остальных пользователей права вызова функции. 
revoke execute on function generate_hash(text[]) from public;


--? Перечень ролей пользователей.
create table fish_shop.role (
	hash_key	uuid,
	actual_from	timestamp default localtimestamp,
	actual_to	timestamp default '9999-12-31 23:59:59.999'::timestamp,
	code		int2,
	name		text not null
);
--? Запрет на проведение каких-либо операций с данными таблицы.
revoke all on fish_shop.role from public;

comment on table fish_shop.role is 'Перечень ролей пользователей';

comment on column fish_shop.role.hash_key is	'Уникальный хеш сущности';
comment on column fish_shop.role.actual_from is	'Дата начала действия роли';
comment on column fish_shop.role.actual_to is	'Окончание действия роли';
comment on column fish_shop.role.code is		'Код роли';
comment on column fish_shop.role.name is		'Наименование роли';

--? Функция записи роли в таблицу.
create or replace function  fish_shop.role_insert (
	p_name			text,
	p_code			int2,
	p_actual_from	timestamp
)
returns void
security definer
as $$
declare
	"check"		uuid;
	"exists"	bool;
	last_date	timestamp;
begin
	select
		generate_hash(
			array[
				p_code::text
			]
		)
	into "check";

	select
		exists (
			select
				1
			from fish_shop.role as role
			where
				hash_key = "check"
				and actual_to = '9999-12-31 23:59:59.999'::timestamp
		)
	into "exists";

	select
		actual_to
	from fish_shop.role as role
	where
		hash_key = "check"
	order by
		actual_to desc
	fetch first 1 row only
	into last_date;

	if not "exists"
		then
			insert into fish_shop.role (
				hash_key,
				actual_from,
				code,
				name
			)
				select
					"check",
					greatest(p_actual_from, last_date),
					p_code,
					p_name;
	end if;
end
$$ language plpgsql;
--? Запрет на вызов функции.
revoke execute on function fish_shop.role_insert (text, int2, timestamp) from public;
--? Предоставление возможности вызова функции пользователю.
grant execute on function fish_shop.role_insert (text, int2, timestamp)  to "user";

--? Функция деактуализации ролей пользователей.
create or replace function  fish_shop.role_delete (
	p_name			text,
	p_code			int2,
	p_actual_to		timestamp
)
returns void
security definer
as $$
declare
	"check"		uuid;
	"exists"	bool;
begin
	select
		generate_hash(
			array[
				p_code::text
			]
		)
	into "check";

	select
		exists (
			select
				1
			from fish_shop.role as role
			where
				hash_key = "check"
		)
	into "exists";

	if "exists"
		then
			update fish_shop.role
			set
				actual_to = greatest(p_actual_to, actual_from + interval '1 day')
			where
				hash_key = "check";
	end if;
end
$$ language plpgsql;
--? Запрет на вызов функции.
revoke execute on function fish_shop.role_delete (text, int2, timestamp) from public;
--? Предоставление возможности вызова функции пользователю.
grant execute on function fish_shop.role_delete (text, int2, timestamp)  to "user";

--? Функция переименования ролей пользователей.
create or replace function  fish_shop.role_rename (
	p_name			text,
	p_code			int2,
	p_date			timestamp
)
returns void
security definer
as $$
declare
	"check"		uuid;
	"exists"	bool;
begin
	select
		generate_hash(
			array[
				p_code::text
			]
		)
	into "check";

	select
		exists (
			select
				1
			from fish_shop.role as role
			where
				hash_key = "check"
		)
	into "exists";

	if "exists"
		then
			update fish_shop.role
			set
				name = p_name
			where
				hash_key = "check"
				and p_date between actual_from and actual_to;
	end if;
end
$$ language plpgsql;
--? Запрет на вызов функции.
revoke execute on function fish_shop.role_rename (text, int2, timestamp) from public;
--? Предоставление возможности вызова функции пользователю.
grant execute on function fish_shop.role_rename (text, int2, timestamp) to "user";

--? Функция получения ролей пользователей.
create or replace function  fish_shop.role_show (
	p_name			text,
	p_code			int2,
	p_date			timestamp
)
returns table (
	actual_from timestamp,
	array_to	timestamp,
	code	int2,
	name	text
)
security definer
as $$
declare
	"check"		uuid;
begin
	select
		generate_hash(
			array[
				p_code::text
			]
		)
	into "check";

	begin
		return query
			select
				actual_from,
				actual_to
				code,
				name
			from fish_shop.role
			where
				p_date between actual_from and actual_to
				and hash_key = "check";
	end;
end
$$ language plpgsql;
--? Запрет на вызов функции.
revoke execute on function fish_shop.role_show (text, int2, timestamp) from public;
--? Предоставление возможности вызова функции пользователю.
grant execute on function fish_shop.role_show (text, int2, timestamp) to "user";