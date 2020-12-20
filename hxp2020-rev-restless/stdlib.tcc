// Standard library
namespace stdlib
{
	namespace impl
	{
		may_inline static inline void print(const char *message, std::size_t length)
		{
			unsigned long result;
			__asm__ volatile (
				"syscall;"
				: "=a"(result)
				: "a"(__NR_write), "D"(1), "S"(message), "d"(length)
				: "rcx", "r11"
			);
		}

		[[deprecated]] may_inline static inline void describe(core::tagged_ptr value)
		{
			switch (value.type)
			{
				case core::TAG_NIL:
					print("(nil)", 5);
					break;
				case core::TAG_RAW:
					print("(raw pointer)", 13);
					break;
				case core::TAG_TUPLE:
					print("(tuple)", 7);
					break;
				case core::TAG_FUNCTION:
					print("(function)", 10);
					break;
				case core::TAG_COROUTINE:
					print("(coroutine)", 11);
					break;
				case core::TAG_STRING:
					print("(string)", 8);
					break;
				case core::TAG_INT:
					print("(int)", 5);
					break;
			}
		}
	}

	// Type safety asserts
	#define assert_list(v) assert((v).type == core::TAG_NIL || ((v).type == core::TAG_TUPLE && (v).arg == 2))
	#define assert_int(v) assert((v).type == core::TAG_INT)
	#define assert_string(v) assert((v).type == core::TAG_STRING)
	#define assert_tuple(v) assert((v).type == core::TAG_TUPLE)
	#define assert_function(v) assert((v).type == core::TAG_FUNCTION)

	// List creation helpers - compile time
	always_inline static inline core::tagged_ptr list_create()
	{
		UNSAFE_I_KNOW_WHAT_I_AM_DOING_LET_ME_RETURN core::nil;
	}

	template <typename T, typename... Ts>
	always_inline static inline core::tagged_ptr list_create(T front, Ts... ts)
	{
		UNSAFE_I_KNOW_WHAT_I_AM_DOING_LET_ME_RETURN core::tuple_create(front, list_create(ts...));
	}

	// List basics
	function(car, core::tagged_ptr list)
	{
		assert_list(list);
		core::function_return(!!list ? list[0] : core::nil);
	}

	function(cdr, core::tagged_ptr list)
	{
		assert_list(list);
		core::function_return(!!list ? list[1] : core::nil);
	}

	function(cadr, core::tagged_ptr list)
	{
		assert_list(list);
		core::function_return(stdlib::car(stdlib::cdr(list)));
	}

	function(cddr, core::tagged_ptr list)
	{
		assert_list(list);
		core::function_return(stdlib::cdr(stdlib::cdr(list)));
	}

	function(caddr, core::tagged_ptr list)
	{
		assert_list(list);
		core::function_return(stdlib::car(stdlib::cddr(list)));
	}

	function(cdddr, core::tagged_ptr list)
	{
		assert_list(list);
		core::function_return(stdlib::cdr(stdlib::cddr(list)));
	}

	function(cadddr, core::tagged_ptr list)
	{
		assert_list(list);
		core::function_return(stdlib::car(stdlib::cdddr(list)));
	}

	function(cddddr, core::tagged_ptr list)
	{
		assert_list(list);
		core::function_return(stdlib::cdr(stdlib::cdddr(list)));
	}

	function(length, core::tagged_ptr list)
	{
		assert_list(list);
		if (!list)
			core::function_return(0_t);
		std::uint32_t length = 0;
		do
		{
			++length;
			list = stdlib::cdr(list);
		}
		while (list);
		core::function_return(core::int_create(length));
	}

	function(join, core::tagged_ptr list, core::tagged_ptr other)
	{
		assert_list(list);
		assert_list(other);
		if (!list)
			core::function_return(other);
		core::tagged_ptr head = list;
		for (; stdlib::cdr(list); list = stdlib::cdr(list))
			assert_list(list);
		list[1] = other;
		core::function_return(head);
	}

	function(append, core::tagged_ptr list, core::tagged_ptr item)
	{
		assert_list(list);
		if (!list)
			core::function_return(stdlib::list_create(item));
		core::function_return(stdlib::join(list, stdlib::list_create(item)));
	}

	function(prepend, core::tagged_ptr list, core::tagged_ptr item)
	{
		assert_list(list);
		core::function_return(core::tuple_create(item, list));
	}

	function(detach_modify, core::tagged_ptr list, core::tagged_ptr at)
	{
		assert_list(list);
		assert_int(at);

		std::size_t remaining = core::int_value<std::size_t>(at);
		if (!remaining)
			core::function_return(core::tuple_create(core::nil, list));
		else if (remaining == 1)
			core::function_return(list);
		core::tagged_ptr head = list, previous = list;
		for (; remaining && !!list; --remaining)
		{
			previous = list;
			list = stdlib::cdr(list);
		}
		previous[1] = core::nil;
		core::function_return(core::tuple_create(head, list));
	}

	function(detach_end_modify, core::tagged_ptr list, core::tagged_ptr at)
	{
		assert_list(list);
		assert_int(at);
		core::function_return(stdlib::detach_modify(list, core::int_sub(stdlib::length(list), at)));
	}

	function(apply_tuple, core::tagged_ptr fn, core::tagged_ptr tuple)
	{
		assert_tuple(tuple);
		assert_function(fn);
		if (!tuple.arg)
			core::function_return(fn());
		for (std::uint16_t i = 0; i < tuple.arg; ++i)
			fn = fn(tuple[i]);
		core::function_return(fn);
	}

	function(map_tuple, core::tagged_ptr fn, core::tagged_ptr tuple)
	{
		assert_tuple(tuple);
		assert_function(fn);
		auto result = core::tuple_create(tuple.arg);
		for (std::uint16_t i = 0; i < tuple.arg; ++i)
			result[i] = fn(tuple[i]);
		core::function_return(result);
	}

	function(reduce_tuple, core::tagged_ptr fn, core::tagged_ptr tuple)
	{
		assert_tuple(tuple);
		assert_function(fn);
		assert(tuple.arg >= 2);
		core::tagged_ptr value = fn(tuple[0], tuple[1]);
		for (std::uint16_t i = 2; i < tuple.arg; ++i)
			value = fn(value, tuple[i]);
		core::function_return(value);
	}

	function(apply, core::tagged_ptr fn, core::tagged_ptr list)
	{
		assert_list(list);
		assert_function(fn);
		if (!list)
			core::function_return(fn());
		while (list)
		{
			fn = fn(stdlib::car(list));
			list = stdlib::cdr(list);
		}
		core::function_return(fn);
	}

	function(map, core::tagged_ptr fn, core::tagged_ptr list)
	{
		assert_list(list);
		assert_function(fn);
		if (!list)
			core::function_return(core::nil);

		auto result = fn(stdlib::car(list)); // Ensure this is sequenced before the recursion.

		core::function_return(
			core::tuple_create(
				result,
				stdlib::map(fn, stdlib::cdr(list))
			)
		);
	}

	function(reduce, core::tagged_ptr fn, core::tagged_ptr list)
	{
		assert_list(list);
		assert_function(fn);
		assert(!!list && !!stdlib::cdr(list));
		core::tagged_ptr value = fn(stdlib::car(list), stdlib::cadr(list));
		list = stdlib::cddr(list);
		for (; list; list = stdlib::cdr(list))
			value = fn(value, stdlib::car(list));
		core::function_return(value);
	}

	function(starmap, core::tagged_ptr fn, core::tagged_ptr lists)
	{
		assert_tuple(lists);
		assert_function(fn);
		if (!lists)
			core::function_return(core::nil);
		for (std::uint16_t i = 0; i < lists.arg; ++i)
			if (!lists[i])
				core::function_return(core::nil);

		auto result = stdlib::apply_tuple(fn, stdlib::map_tuple(stdlib::car, lists)); // Ensure this is sequenced before the recursion.

		core::function_return(
			core::tuple_create(
				result,
				stdlib::starmap(fn, stdlib::map_tuple(stdlib::cdr, lists))
			)
		);
	}

	function(zip, core::tagged_ptr a, core::tagged_ptr b)
	{
		assert_list(a);
		assert_list(b);
		if (!a || !b)
			core::function_return(core::nil);
		core::function_return(
			core::tuple_create(
				core::tuple_create(stdlib::car(a), stdlib::car(b)),
				stdlib::zip(stdlib::cdr(a), stdlib::cdr(b))
			)
		);
	}

	function(at, core::tagged_ptr list, core::tagged_ptr idx)
	{
		assert_list(list);
		assert_int(idx);
		std::size_t index = core::int_value<std::size_t>(idx);
		while (list)
		{
			if (!index)
				core::function_return(stdlib::car(list));
			list = stdlib::cdr(list);
			--index;
		}
		__builtin_trap();
	}

	function(list_split, core::tagged_ptr list, core::tagged_ptr size)
	{
		assert_list(list);
		assert_int(size);
		std::uint32_t block_size = core::int_value<std::uint32_t>(size);

		core::tagged_ptr out = core::nil;
		core::tagged_ptr cur = core::nil;
		std::uint32_t iter = 0;
		while (!!list)
		{
			cur = stdlib::append(cur, stdlib::car(list));
			if (++iter == block_size)
			{
				iter = 0;
				out = stdlib::append(out, cur);
				cur = core::nil;
			}
			list = stdlib::cdr(list);
		}

		if (!!cur)
			out = stdlib::append(out, cur);

		core::function_return(out);
	}

	function(list_to_tuple, core::tagged_ptr list)
	{
		assert_list(list);
		std::size_t size = core::int_value<std::size_t>(stdlib::length(list));
		assert(size <= core::tagged_ptr_max_arg);
		core::tagged_ptr tuple = core::tuple_create(size);

		for (std::size_t index = 0; index < size; ++index)
		{
			tuple[index] = stdlib::car(list);
			list = stdlib::cdr(list);
		}

		core::function_return(tuple);
	}

	function(list_repeat, core::tagged_ptr value, core::tagged_ptr count)
	{
		assert_int(count);
		std::size_t size = core::int_value<std::size_t>(count);
		if (!size)
			core::function_return(stdlib::list_create());
		core::tagged_ptr list = stdlib::list_create(value);
		core::tagged_ptr head = list;
		for (std::size_t index = 1; index < size; ++index, list = list[1])
			list[1] = stdlib::list_create(value);
		core::function_return(head);
	}

	// Booleans
	static core::tagged_ptr yes = 1_t;
	static core::tagged_ptr no = 0_t;
	function(check, core::tagged_ptr predicate)
	{
		core::function_return(!!predicate && core::int_value<std::uint32_t>(predicate) ? predicate : core::nil);
	}

	// Comparisons
	function(equal, core::tagged_ptr a, core::tagged_ptr b)
	{
		if (a.raw_data() == b.raw_data())
			core::function_return(yes);
			/// XXX: When we get bigints, implement integer comparison in a non-raw_data()-based method. Right now, this lets us avoid issues with signedness, etc.
		else if (a.type != b.type)
			core::function_return(no);
		else if (a.type == core::TAG_NIL)
			core::function_return(yes);
		else if (a.type == core::TAG_STRING)
		{
			const char *aa = reinterpret_cast<const char *>(a.value());
			const char *bb = reinterpret_cast<const char *>(b.value());
			for (; *aa && *bb; ++aa, ++bb)
				if (*aa != *bb)
					core::function_return(no);
			core::function_return(*aa == *bb ? yes : no);
		}
		else if (a.type == core::TAG_TUPLE)
		{
			if (a.arg != b.arg)
				core::function_return(no);
			for (std::size_t index = 0; index < a.arg; ++index)
				if (!check(equal(a[index], b[index])))
					core::function_return(no);
			core::function_return(yes);
		}
		core::function_return(no);
	}

	// String tools
	function(string_length, core::tagged_ptr str)
	{
		assert_string(str);
		std::uint32_t length = 0;
		for (const char *data = core::string_value(str); *data; ++data)
			++length;
		core::function_return(core::int_create(length));
	}

	function(print, core::tagged_ptr str)
	{
		assert_string(str);
		stdlib::impl::print(core::string_value(str), core::int_value<std::uint32_t>(stdlib::string_length(str)));
	}

	function(println, core::tagged_ptr str)
	{
		stdlib::print(str);
		stdlib::impl::print("\n", 1);
	}

	function(string_cut, core::tagged_ptr subject_arg, core::tagged_ptr pattern_arg)
	{
		assert_string(subject_arg);
		assert_string(pattern_arg);
		const char *subject = reinterpret_cast<const char *>(subject_arg.value());
		const char *pattern = reinterpret_cast<const char *>(pattern_arg.value());
		assert(pattern[1] == 0 && pattern[0] != 0);
		char split_at = pattern[0];
		core::tagged_ptr list = core::nil;
		const char *it = subject;
		for (; *it; ++it)
		{
			if (*it == split_at)
			{
				list = stdlib::append(list, core::string_intern(subject, it - subject));
				subject = it + 1;
			}
		}
		if (subject != it)
			list = stdlib::append(list, core::string_intern(subject, it - subject));
		core::function_return(list);
	}

	function(list_to_string, core::tagged_ptr list)
	{
		assert_list(list);
		if (list.type != core::TAG_TUPLE)
			core::function_return(core::nil);

		std::uint32_t i = 0;
		core::tagged_ptr s = core::string_intern(core::int_value<std::uint32_t>(stdlib::length(list)));
		do
		{
			reinterpret_cast<char *>(s.value())[i++] = static_cast<char>(core::int_value<std::uint32_t>(stdlib::car(list)));
			list = stdlib::cdr(list);
		}
		while (!!list);
		core::function_return(s);
	}

	function(string_to_list, core::tagged_ptr str)
	{
		assert_string(str);
		core::tagged_ptr result = core::nil;
		for (std::uint32_t i = core::int_value<std::uint32_t>(stdlib::string_length(str)); i > 0; --i)
			result = stdlib::prepend(result, core::int_create(static_cast<std::uint32_t>(core::string_value(str)[i - 1])));
		core::function_return(result);
	}
}
