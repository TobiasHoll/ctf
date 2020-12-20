#define __flag_hash__ "\x30\x6f\x03\x06\xbc\x6b\x9b\x57\x1a\x52\xf0\x59\x67\x98\xae\x42"
#define __flag_leak__ \
	51_t, 284_t, 1009_t, 47_t, 374_t, 893_t, 879_t, 284_t, 186_t, 476_t, 716_t, \
	795_t, 1023_t, 559_t, 494_t, 345_t, 867_t, 436_t, 679_t, 715_t, 779_t, 357_t, \
	198_t, 603_t, 390_t, 713_t, 744_t, 864_t, 1_t, 996_t, 260_t, 812_t, 936_t, \
	424_t, 909_t, 970_t, 743_t, 706_t, 474_t, 256_t, 815_t, 316_t, 115_t, 921_t, \
	853_t, 581_t, 476_t, 177_t, 647_t, 414_t, 174_t, 629_t, 465_t, 130_t, 825_t, \
	183_t, 706_t, 809_t, 135_t, 38_t, 28_t, 875_t, 339_t, 941_t
#define __flag_length__ 30_t

function(resume, core::tagged_ptr co, core::tagged_ptr arg)
{
	core::function_return(core::coroutine_resume(co, arg)[0]);
}

coroutine(output, core::tagged_ptr message)
{
	for (;;)
	{
		stdlib::print(message);
		message = core::coroutine_resume(core::coroutine_whence(), message)[0];
	}
}

static auto success_message = core::string_create("\x1b[32;1m:)\x1b[0m\n");
static auto failure_message = core::string_create("\x1b[31;1m:(\x1b[0m\n");
coroutine(quit, core::tagged_ptr status)
{
	core::coroutine_resume(output, stdlib::check(status) ? success_message : failure_message);
	std::exit(0);
}

function(fail)
{
	core::coroutine_resume(quit, stdlib::no);
}

coroutine(extract_part, core::tagged_ptr flag, core::tagged_ptr prefix_checker)
{
	core::tagged_ptr result = stdlib::string_cut(
		core::coroutine_resume(
			prefix_checker,
			stdlib::string_cut(
				flag,
				core::string_create("{")
			)
		)[0],
		core::string_create("}")
	);
	core::coroutine_resume(core::coroutine_whence(), result);
}

function(bytes_to_le, core::tagged_ptr chunk)
{
	core::tagged_ptr result = stdlib::car(chunk);
	core::tagged_ptr shift = 8_t;
	for (chunk = stdlib::cdr(chunk); chunk; chunk = stdlib::cdr(chunk), shift = core::int_add(shift, 8_t))
		result = core::int_or(result, core::int_shl(stdlib::car(chunk), shift));
	core::function_return(result);
}

function(le_to_bytes, core::tagged_ptr value)
{
	core::tagged_ptr mask = 0xff_t;
	core::tagged_ptr shift = 8_t;
	core::tagged_ptr out = stdlib::list_create();
	for (; stdlib::check(value); value = core::int_shr(value, shift))
		out = stdlib::append(out, core::int_and(value, mask));
	core::function_return(out);
}

function(md5_small_chunk, core::tagged_ptr message)
{
	core::function_return(stdlib::map(bytes_to_le, stdlib::list_split(message, 4_t)));
}

coroutine(md5_prepare, core::tagged_ptr message)
{
	core::tagged_ptr length = stdlib::string_length(message);
	core::tagged_ptr prepared = stdlib::reduce_tuple(
		stdlib::join,
		core::tuple_create(
			stdlib::string_to_list(message),
			stdlib::list_create(0x80_t),
			stdlib::list_repeat(
				0_t,
				core::int_sub(64_t, core::int_mod(core::int_add(9_t, length), 64_t))
			),
			stdlib::detach_modify(stdlib::join(le_to_bytes(core::int_mul(length, 8_t)), stdlib::list_repeat(0_t, 8_t)), 8_t)[0]
		)
	);
	core::coroutine_resume(core::coroutine_whence(), stdlib::list_split(prepared, 64_t));
}

function(fold_left, core::tagged_ptr fn, core::tagged_ptr init, core::tagged_ptr args)
{
	core::function_return(stdlib::reduce(fn, stdlib::prepend(args, init)));
}

function(s_generator, core::tagged_ptr count, core::tagged_ptr init, core::tagged_ptr next_value, core::tagged_ptr next_gen)
{
	core::tagged_ptr generator_fn = lambda([count, init, next_value, next_gen, total = count]() mutable {
		core::tagged_ptr times = count, current = init;
		for (; !stdlib::check(stdlib::equal(times, 1_t)); times = core::int_sub(times, 1_t), current = next_value(current))
			core::coroutine_resume(core::coroutine_whence(), next_value(current));
		total = core::int_sub(total, 1_t);
		core::coroutine_resume_with(
			core::coroutine_whence(),
			core::tuple_create(next_value(current)),
			stdlib::check(total) ? core::coroutine_create(core::current_coroutine_function()) : next_gen
		);
	});
	core::function_return(core::coroutine_create(generator_fn));
}

function(mod_add, core::tagged_ptr a, core::tagged_ptr b)
{
	core::function_return(core::int_and(core::int_add(a, b), 0xffffffff_t));
}

function(make_storage_continuation)
{
	core::function_return(core::coroutine_create(lambda([](core::tagged_ptr arg) {
		core::tagged_ptr stored = stdlib::list_create(arg);
		for (;;)
			stored = stdlib::prepend(stored, core::coroutine_resume(core::coroutine_whence(), stored)[0]);
	})));
}

function(identity, core::tagged_ptr arg)
{
	core::function_return(arg);
}

function(rol_32, core::tagged_ptr value, core::tagged_ptr by)
{
	core::function_return(core::int_and(core::int_or(core::int_shl(value, by), core::int_shr(value, core::int_sub(32_t, by))), 0xffffffff_t));
}

function(make_generator_exit, core::tagged_ptr return_to)
{
	core::function_return(core::coroutine_create(lambda([return_to] {
		core::coroutine_resume(return_to, core::nil);
	})));
}

function(ceil_sin, core::tagged_ptr value)
{
	core::function_return(core::int_create(static_cast<std::uint32_t>(
		std::ceil(std::sin(static_cast<double>(core::int_value<std::uintptr_t>(value))))
	)));
}

function(ceil_mul_sqrt, core::tagged_ptr value, core::tagged_ptr mul_by)
{
	core::function_return(core::int_create(static_cast<std::uint32_t>(
		std::ceil(static_cast<double>(core::int_value<std::uintptr_t>(mul_by)) * std::sqrt(static_cast<double>(core::int_value<std::uintptr_t>(value))))
	)));
}

function(floor_mul_abs_sin, core::tagged_ptr value, core::tagged_ptr mul_by)
{
	core::function_return(core::int_create(static_cast<std::uint32_t>(
		std::floor(static_cast<double>(core::int_value<std::uintptr_t>(mul_by)) * std::fabs(std::sin(core::int_value<std::uint32_t>(value))))
	)));
}

function(make_md5_compressor, core::tagged_ptr store_masked)
{
	core::function_return(core::coroutine_create(lambda([store_masked, from = core::current_coroutine()](core::tagged_ptr state, core::tagged_ptr chunk) {
		reset: ; /// XXX: coroutine_resume(this, state, chunk) should work like this, but I didn't test it
		core::tagged_ptr a = stdlib::car(state), b = stdlib::cadr(state), c = stdlib::caddr(state), d = stdlib::cadddr(state);
		core::tagged_ptr S = s_generator(4_t, 2_t,
			lfn(i, core::int_add(i, 5_t)),
			s_generator(4_t, 2_t,
				lfn(i, core::int_add(i, core::int_add(2_t, core::int_div(ceil_mul_sqrt(core::int_sub(i, 1_t), 2_t), 2_t)))),
				s_generator(4_t, core::int_neg(1_t),
					lfn(i, core::int_add(i, core::int_add(5_t, core::int_mul(2_t, ceil_sin(core::int_mul(2_t, i)))))),
					s_generator(4_t, 3_t,
						lfn(i, core::int_add(i, core::int_add(2_t, core::int_div(ceil_mul_sqrt(core::int_sub(i, 1_t), 2_t), 2_t)))),
						make_generator_exit(core::current_coroutine())))));
		core::tagged_ptr G = s_generator(4_t,
			lfn(bcdi, core::tuple_create(core::int_or(core::int_and(bcdi[0], bcdi[1]), core::int_and(core::int_not(bcdi[0]), bcdi[2])), bcdi[3])),
			identity,
			s_generator(4_t,
				lfn(bcdi, core::tuple_create(core::int_or(core::int_and(bcdi[0], bcdi[2]), core::int_and(bcdi[1], core::int_not(bcdi[2]))), core::int_and(core::int_add(core::int_mul(bcdi[3], 5_t), 1_t), 0xf_t))),
				identity,
				s_generator(4_t,
					lfn(bcdi, core::tuple_create(core::int_xor(core::int_xor(bcdi[0], bcdi[1]), bcdi[2]), core::int_and(core::int_add(core::int_mul(bcdi[3], 3_t), 5_t), 0xf_t))),
					identity,
					s_generator(4_t,
						lfn(bcdi, core::tuple_create(core::int_xor(bcdi[1], core::int_or(bcdi[0], core::int_not(bcdi[2]))), core::int_and(core::int_mul(bcdi[3], 7_t), 0xf_t))),
						identity,
						make_generator_exit(core::current_coroutine())))));
		core::tagged_ptr M = md5_small_chunk(chunk);
		core::tagged_ptr K = lfn(i, floor_mul_abs_sin(core::int_add(i, 1_t), 0x100000000_t));
		for (core::tagged_ptr i = 0_t;; i = core::int_add(i, 1_t))
		{
			core::tagged_ptr s = core::coroutine_resume(S)[0];
			core::tagged_ptr Fg = core::coroutine_resume(G)[0];
			if (!s || !Fg)
			{
				state = stdlib::starmap(mod_add, core::tuple_create(state, stdlib::list_create(a, b, c, d)));
				core::tagged_ptr new_args = core::coroutine_resume_with(from, state, core::nil);
				state = stdlib::car(new_args);
				chunk = stdlib::cdr(new_args);
				goto reset;
			}
			core::tagged_ptr new_value = mod_add(
				rol_32(
					mod_add(
						mod_add(
							mod_add(
								a,
								stdlib::car(Fg(core::tuple_create(b, c, d, i)))
							),
							stdlib::at(
								M,
								stdlib::cdr(Fg(core::tuple_create(b, c, d, i)))
							)
						),
						K(i)
					),
					s
				),
				b
			);
			core::coroutine_resume(store_masked, core::int_and(0x3ff_t, new_value));
			a = d;
			d = c;
			c = b;
			b = new_value;
		}
	})));
}

function(le_to_bytes_32, core::tagged_ptr value)
{
	core::function_return(stdlib::detach_modify(stdlib::join(le_to_bytes(value), stdlib::list_repeat(0_t, 4_t)), 4_t)[0]);
}

coroutine(md5, core::tagged_ptr chunks)
{
	core::tagged_ptr from = core::coroutine_whence();
	core::tagged_ptr storage = make_storage_continuation();
	core::tagged_ptr state = stdlib::list_create(0x67452301_t, 0xefcdab89_t, 0x98badcfe_t, 0x10325476_t);
	core::tagged_ptr compressor = make_md5_compressor(storage);

	core::tagged_ptr compress_more = lambda([compressor](core::tagged_ptr state, core::tagged_ptr arg) { core::function_return(core::coroutine_resume(compressor, state, arg)); });

	core::coroutine_resume(
		from,
		stdlib::list_to_string(stdlib::reduce(
			stdlib::join,
			stdlib::map(
				le_to_bytes_32,
				fold_left(compress_more, state, chunks)
			)
		)),
		storage
	);
}

coroutine(check_flag, core::tagged_ptr flag)
{
	core::tagged_ptr verify_flag_format = core::coroutine_create(lambda([](core::tagged_ptr parts) {
		core::tagged_ptr empty_string = core::string_create("");
		if (!parts || !stdlib::check(stdlib::equal(stdlib::car(parts), core::string_create("hxp"))))
			core::coroutine_resume(check_flag, quit, stdlib::no);
		else if (!stdlib::cdr(parts) || stdlib::check(stdlib::equal(stdlib::cadr(parts), empty_string)))
			core::coroutine_resume(check_flag, quit, stdlib::no);
		else if (core::tagged_ptr res = core::coroutine_resume(core::coroutine_whence(), stdlib::cadr(parts))[0];
			!res || !stdlib::cdr(res) || stdlib::check(stdlib::equal(stdlib::cadr(res), empty_string)) || !stdlib::check(stdlib::equal(stdlib::string_length(stdlib::car(res)), __flag_length__)) || stdlib::cddr(res))
			core::coroutine_resume(check_flag, md5_prepare, stdlib::car(res));
		else
			core::coroutine_resume(check_flag, quit, stdlib::no);
	}));
	core::tagged_ptr prepared = stdlib::apply_tuple(resume, core::coroutine_resume(extract_part, flag, verify_flag_format));
	core::tagged_ptr hash = core::coroutine_resume(md5, prepared);
	core::coroutine_resume(
		stdlib::check(stdlib::equal(stdlib::car(hash), core::string_create(__flag_hash__)))
			? check_flag
			: quit,
		stdlib::no
	);
	core::tagged_ptr dummy = core::nil;
	core::coroutine_resume(
		quit,
		stdlib::equal(
			core::coroutine_resume(stdlib::cdr(hash), dummy)[0],
			stdlib::list_create(dummy, __flag_leak__)
		)
	);
}

coroutine(main_coroutine, core::tagged_ptr argv)
{
	core::tagged_ptr flag = stdlib::cadr(argv);
	if (!flag)
		core::coroutine_resume(quit, stdlib::no);
	core::coroutine_resume(check_flag, flag);
}
