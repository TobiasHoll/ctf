#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <utility>

extern "C"
{
	#include <sys/resource.h>
	#include <sys/syscall.h>
	#include <sys/user.h>
}

#define __stringify_impl(arg) #arg
#define __stringify(arg) __stringify_impl(arg)

#define ensure_read(reg, var) \
	__asm__ ("movq %%" reg ", %[value];" : [value]"+r"(var))
#define ensure_write(reg, var) \
	__asm__ ("movq %[value], %%" reg ";" : [value]"+r"(var));
#define ensure_read_memory(reg, mem) \
	__asm__ ("movq %%" reg ", %[value];" : [value]"+m"(mem))
#define ensure_write_memory(reg, mem) \
	__asm__ ("movq %[value], %%" reg ";" : [value]"+m"(mem));

#define barrier() __asm__ volatile ("" ::: "memory");

// Clang doesn't support GCC's inline asm fully (this is so we can switch compilers if it turns out to be necessary)
#ifdef __clang__
	#define JMP(name) "jmp %c" name ";"
	#define CALL(name) "call %c" name ";"
#else
	#define JMP(name) "jmp %p" name ";"
	#define CALL(name) "call %p" name ";"
#endif

#if defined(__AVX512F__)
#define zmm_clobbers \
	"zmm0", "zmm1", "zmm2", "zmm3", "zmm4", "zmm5", "zmm6", "zmm7", "zmm8", "zmm9", "zmm10", "zmm11", "zmm12", "zmm13", "zmm14", "zmm15", \
	"zmm16", "zmm17", "zmm18", "zmm19", "zmm20", "zmm21", "zmm22", "zmm23", "zmm24", "zmm25", "zmm26", "zmm27", "zmm28", "zmm29", "zmm30", "zmm31",
#elif defined(__SSE__)
#define zmm_clobbers \
	"zmm0", "zmm1", "zmm2", "zmm3", "zmm4", "zmm5", "zmm6", "zmm7", "zmm8", "zmm9", "zmm10", "zmm11", "zmm12", "zmm13", "zmm14", "zmm15",
#else
#define zmm_clobbers
#endif

#define always_inline [[gnu::always_inline]]

#if defined(NO_INLINE)
	#define may_inline [[gnu::noinline]]
#elif defined(FORCE_INLINE)
	#define may_inline [[gnu::always_inline]]
#else
	#define may_inline
#endif

#if defined(VERBOSE_DEBUG) // I think if you enable this everything breaks, so consider assert(...) really more of an annotation of my assumptions...
	#include <cstdio>
	#define assert(...) do { if (!(__VA_ARGS__)) { fprintf(stderr, "Assertion failed: %s in %s at %s:%d\n", __stringify(__VA_ARGS__), __PRETTY_FUNCTION__, __FILE__, __LINE__); __builtin_trap(); } } while (0)
	#define bad_memory 0xdeaddeaddead
#elif defined(STRING_DEBUG) // This is slightly less straightforward, but leaves the assert string in the binary for printing
	#define assert(...) do { if (!(__VA_ARGS__)) { __asm__ volatile ("ud2; .asciz \"Assertion failed: " __stringify(__VA_ARGS__) " at " __FILE__ ":" __stringify(__LINE__) "\";" :::); } } while (0)
	#define bad_memory 0xdeaddeaddead
#elif defined(SYMBOL_DEBUG) // This should make the final binary virtually indistinguishable from one without assert information, except for the symbol information
	#define assert(...) do { \
		__asm__ volatile ( \
			".pushsection .rodata;" \
			"assert_%=_msg:;" \
			".asciz \"" __stringify(__VA_ARGS__) " at " __FILE__ ":" __stringify(__LINE__) "\";" \
			".popsection;" \
			"assert_%=:;" \
			::: \
		); \
		if (!(__VA_ARGS__)) __builtin_trap(); \
	} while (0)
	#define bad_memory 0xdeaddeaddead
#elif defined(HAVE_ASSERTS) // Asserts, but without extra information
	#define assert(...) do { if (!(__VA_ARGS__)) __builtin_trap(); } while (0)
	#define bad_memory 0xdeaddeaddead
#else // Don't even assert (but compute side effects all the same).
	#define assert(...) do { if (__builtin_expect((__VA_ARGS__), 1)) {} } while (0)
	#define bad_memory 0x0
#endif

// Fixed register assignments
#define allocator_head_register "r15"
#define per_task_register "r14"

always_inline static inline std::uintptr_t *preserve_registers()
{
	std::uintptr_t *memory = reinterpret_cast<std::uintptr_t *>(alloca(16));
	ensure_read_memory(allocator_head_register, memory[0]);
	ensure_read_memory(per_task_register, memory[1]);
	return memory;
}

always_inline static inline void restore_registers(std::uintptr_t *storage)
{
	std::uintptr_t *memory = reinterpret_cast<std::uintptr_t *>(storage);
	ensure_write_memory(allocator_head_register, memory[0]);
	ensure_write_memory(per_task_register, memory[1]);
}

// <cpuid.h> did not inline properly and had lots of clutter so here's mine.
#define cpuid(leaf, subleaf, eax, ebx, ecx, edx) \
	__asm__ ( \
		"cpuid;" \
		: "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) \
		: "a"(leaf), "c"(subleaf) \
	)
#define cpuid_simple(leaf, eax, ebx, ecx, edx) \
	__asm__ ( \
		"cpuid;" \
		: "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) \
		: "a"(leaf) \
	)
#define cpuid_max(eax) \
	do { \
		std::uint32_t ebx, ecx, edx; \
		cpuid_simple(0, eax, ebx, ecx, edx); \
	} while (0) // NB: This complication is necessary because GCC doesn't understand clobbering register variables...

#define bit_XSAVE (1 << 26)
#define bit_OSXSAVE (1 << 27)

static const std::size_t xsave_area_size = []() {
	auto storage = preserve_registers();

	std::uint32_t eax = 0, ebx = 0, ecx = 0, edx = 0;
	cpuid_max(eax);
	if (eax < 13)
		__builtin_trap();

	cpuid_simple(1, eax, ebx, ecx, edx);
	if ((ecx & (bit_XSAVE | bit_OSXSAVE)) != (bit_XSAVE | bit_OSXSAVE))
		__builtin_trap();

	cpuid(13, 0, eax, ebx, ecx, edx);
	std::uint64_t supported = static_cast<std::uint64_t>(edx) << 32 | eax;
	std::size_t size = 64 + 512;

	for (unsigned subleaf = 2; subleaf < 64; ++subleaf)
	{
		if ((supported & (1U << subleaf)) == 0)
			continue;
		cpuid(13, subleaf, eax, ebx, ecx, edx);
		std::size_t past_the_end = ebx /* offset */ + eax /* size */;
		if (past_the_end > size)
			size = past_the_end;
	}

	if (size & 0x3f)
		size = (size | 0x3f) + 1;

	restore_registers(storage);
	return size;
} ();

// Basic settings
// #define required_stack_size 64 * 1024 * 1024 // Uncomment this to enable setrlimit
#define coroutine_stack_size 16384
#define main_extra_stack_size 8192
#define init_hook_limit 2048

namespace core
{
	// Memory allocation
	inline namespace allocator
	{
		register std::uintptr_t allocator_head asm (allocator_head_register);

		always_inline static inline std::uintptr_t allocate(std::size_t size, std::size_t alignment = 8 /* must be a power of 2 */, std::size_t offset = 0)
		{
			// Since GCC doesn't think that it is necessary to properly update the register (thank you optimizer), we have to do it ourselves...
			// At least it tells you [if you have -Wvolatile-register-var enabled, which is off by default]
			ensure_read(allocator_head_register, allocator_head);
			if (!size)
				return 0;
			allocator_head -= size;
			if (allocator_head % alignment != offset)
				allocator_head -= ((allocator_head % alignment) - offset % alignment + alignment) % alignment;
			for (std::size_t off = 0; off < size; off += 8) // memset, but without libdl.
				*reinterpret_cast<std::size_t *>(allocator_head + off) = 0;
			ensure_write(allocator_head_register, allocator_head);
			return allocator_head;
		}
		template <typename T> struct allocation_type { using type = T*; };
		template <typename T, std::size_t S> struct allocation_type<T[S]> { using type = T*; };
		template <typename T> struct allocation_type<T[0]> { using type = T*; };
		template <typename T> may_inline static inline typename allocation_type<T>::type allocate()
		{
			return reinterpret_cast<typename allocation_type<T>::type>(allocate(sizeof(T), alignof(T) < 8 ? 8 : alignof(T), 0));
		}
	}

	// Data types
	inline namespace tagged_types
	{
		enum type_tag : std::uint8_t
		{
			// Fundamental types
			TAG_NIL,       // (TAG_NIL,       any,                    any) -> This ensures that any unsanitized userspace pointer shows up as 'nil'.
			TAG_RAW,       // (TAG_RAW,       implementation-defined, implementation-defined)
			TAG_TUPLE,     // (TAG_TUPLE,     size of tuple,          array of members)
			// Types related to control flow
			TAG_FUNCTION,  // (TAG_FUNCTION,  unused,                 pointer to struct function)
			TAG_COROUTINE, // (TAG_COROUTINE, unused,                 pointer to struct coroutine)
			// Other types
			TAG_INT,       // (TAG_INT,       signed + bigint size,   value if size is 0 else pointer to data)
			TAG_STRING,    // (TAG_STRING,    interned yes/no,        char pointer)
		};

		struct tagged_ptr
		{
			std::uintptr_t __value : 48;
			std::uint16_t  arg     : 13;
			type_tag       type    : 3;

			may_inline std::uintptr_t raw_data() const volatile { return *reinterpret_cast<const std::uintptr_t *>(const_cast<const tagged_ptr*>(this)); /* The "clean" version was FUBAR, apparently */ }
			may_inline std::uintptr_t value() const volatile { std::uintptr_t out; __asm__ volatile ("movq $0xffffffffffff, %[out]; andq %[raw], %[out]" : [out]"=&r"(out) : [raw]"r"(raw_data())); return out; /* ... same here - we can't cache the mask! */ }
			may_inline operator bool() const volatile { return type != TAG_NIL; }
			template <typename T> may_inline T as() const volatile { return reinterpret_cast<T>(value()); }
			always_inline bool operator==(const tagged_ptr& other) const volatile { return raw_data() == other.raw_data(); }

			// Forward declarations for type support, see below
			may_inline const tagged_ptr& operator[](std::size_t) const volatile;
			may_inline tagged_ptr& operator[](std::size_t);
			template <typename... Args> may_inline tagged_ptr operator()(Args&&... args) const;
		};


		static_assert(sizeof(tagged_ptr *) == sizeof(tagged_ptr), "Tagged pointer is not actually the size of a pointer");

		template <type_tag... Tag> using restricted_tagged_ptr = tagged_ptr; // Might allow type checking certain restrictions in the future

		template <type_tag Tag> constexpr static std::size_t tag_mask = static_cast<std::size_t>(Tag) << (64 - 3);

		constexpr static std::size_t tagged_ptr_max_arg = (static_cast<std::size_t>(1) << 13) - 1;
		constexpr static std::size_t tagged_ptr_value_bytes = 48 / 8;


		always_inline inline const tagged_ptr& tagged_ptr::operator[](std::size_t index) const volatile
		{
			assert(type == TAG_TUPLE && index < arg);
			return reinterpret_cast<tagged_ptr *>(value())[index];
		}

		always_inline inline tagged_ptr& tagged_ptr::operator[](std::size_t index)
		{
			assert(type == TAG_TUPLE && index < arg);
			return reinterpret_cast<tagged_ptr *>(value())[index];
		}
	}

	// Support for basic types used internally by the rest of the machinery
	inline namespace basic_types
	{
		// 'nil' constant
		constexpr static restricted_tagged_ptr<TAG_NIL> nil { 0, 0, TAG_NIL };

		// Tuples
		template <typename... Args>
		may_inline static inline std::enable_if_t<(std::is_same_v<tagged_ptr, std::remove_cv_t<std::remove_reference_t<Args>>> && ...), tagged_ptr> tuple_create(Args&&... args)
		{
			static_assert(sizeof...(Args) <= tagged_ptr_max_arg, "Tuple too large");
			tagged_ptr *backing = allocate<tagged_ptr[sizeof...(Args)]>();
			std::size_t index = 0; ((backing[index++] = args), ...);
			return tagged_ptr { reinterpret_cast<std::uintptr_t>(backing), sizeof...(Args), TAG_TUPLE };
		}

		may_inline static inline restricted_tagged_ptr<TAG_TUPLE> tuple_create(std::size_t size)
		{
			assert(size <= tagged_ptr_max_arg);
			std::uintptr_t backing = allocate(size * sizeof(tagged_ptr));
			return tagged_ptr { backing, static_cast<std::uint16_t>(size), TAG_TUPLE };
		}

		always_inline static inline restricted_tagged_ptr<TAG_TUPLE> tuple_create()
		{
			return tagged_ptr { static_cast<std::uintptr_t>(0), static_cast<std::uint16_t>(0), TAG_TUPLE };
		}

		may_inline static inline restricted_tagged_ptr<TAG_TUPLE> tuple_concat(const restricted_tagged_ptr<TAG_TUPLE>& left, const restricted_tagged_ptr<TAG_TUPLE>& right)
		{
			assert(static_cast<std::size_t>(left.arg + right.arg) <= tagged_ptr_max_arg);
			tagged_ptr *concatenation = reinterpret_cast<tagged_ptr *>(allocate((left.arg + right.arg) * sizeof(tagged_ptr)));
			for (std::size_t i = 0; i < left.arg; ++i)
				concatenation[i] = left[i];
			for (std::size_t j = 0; j < right.arg; ++j)
				concatenation[left.arg + j] = right[j];
			return tagged_ptr { reinterpret_cast<std::uintptr_t>(concatenation), static_cast<std::uint16_t>(left.arg + right.arg), TAG_TUPLE };
		}

		may_inline static inline restricted_tagged_ptr<TAG_TUPLE> tuple_split(const restricted_tagged_ptr<TAG_TUPLE>& tuple, std::uint16_t left_size)
		{
			assert(left_size <= tuple.arg);
			std::uint16_t right_size = tuple.arg - left_size;
			tagged_ptr *left = reinterpret_cast<tagged_ptr *>(allocate(left_size * sizeof(tagged_ptr)));
			tagged_ptr *right = reinterpret_cast<tagged_ptr *>(allocate(right_size * sizeof(tagged_ptr)));
			tagged_ptr *out = reinterpret_cast<tagged_ptr *>(allocate(2 * sizeof(tagged_ptr)));
			for (std::uint16_t i = 0; i < left_size; ++i)
				left[i] = tuple[i];
			for (std::uint16_t i = left_size; i < tuple.arg; ++i)
				right[i - left_size] = tuple[i];
			out[0] = tagged_ptr { reinterpret_cast<std::uintptr_t>(left), left_size, TAG_TUPLE };
			out[1] = tagged_ptr { reinterpret_cast<std::uintptr_t>(right), right_size, TAG_TUPLE };
			return tagged_ptr { reinterpret_cast<std::uintptr_t>(out), 2, TAG_TUPLE };
		}

		constexpr static restricted_tagged_ptr<TAG_TUPLE> empty = { 0, 0, TAG_TUPLE };
	}

	// Per-task state: the current stack frame and coroutine
	inline namespace per_task_data
	{
		struct stack_frame
		{
			restricted_tagged_ptr<TAG_RAW>          return_address;
			restricted_tagged_ptr<TAG_RAW>          stack_address;
			restricted_tagged_ptr<TAG_RAW, TAG_NIL> parent;
		};

		[[gnu::noinline, gnu::naked]] static void invalid_function()
		{
			__builtin_trap();
		}

		may_inline static inline restricted_tagged_ptr<TAG_RAW> make_empty_stack_frame()
		{
			stack_frame *frame = allocate<stack_frame>();
			frame->return_address = tagged_ptr { reinterpret_cast<std::uintptr_t>(invalid_function), 0, TAG_RAW };
			frame->stack_address = tagged_ptr { static_cast<std::uintptr_t>(bad_memory), 0, TAG_RAW };
			frame->parent = nil;
			return tagged_ptr { reinterpret_cast<std::uintptr_t>(frame), 0, TAG_RAW };
		};

		struct per_task
		{
			restricted_tagged_ptr<TAG_RAW>                __current_stack_frame; // TAG_RAW, points to the struct stack_frame.
			restricted_tagged_ptr<TAG_COROUTINE, TAG_NIL> __current_coroutine;   // Contains the current coroutine (if any)
		};

		register per_task *__per_task_data asm (per_task_register);

		always_inline static inline restricted_tagged_ptr<TAG_RAW> current_stack_frame()
		{
			tagged_ptr result;
			__asm__ volatile ("movq %c[offset](%%" per_task_register "), %[into]" : [into]"=r"(result) : [offset]"i"(offsetof(per_task, __current_stack_frame)));
			return result;
		}

		always_inline static inline restricted_tagged_ptr<TAG_COROUTINE, TAG_NIL> current_coroutine()
		{
			tagged_ptr result;
			__asm__ volatile ("movq %c[offset](%%" per_task_register "), %[into]" : [into]"=r"(result) : [offset]"i"(offsetof(per_task, __current_coroutine)));
			return result;
		}

		always_inline static inline restricted_tagged_ptr<TAG_RAW> replace_stack_frame(restricted_tagged_ptr<TAG_RAW> frame)
		{
			assert(frame.type == TAG_RAW);
			ensure_read(per_task_register, __per_task_data);
			auto previous = __per_task_data->__current_stack_frame;
			__per_task_data->__current_stack_frame = frame;
			ensure_write(per_task_register, __per_task_data);
			return previous;
		}

		always_inline static inline restricted_tagged_ptr<TAG_COROUTINE, TAG_NIL> replace_coroutine(restricted_tagged_ptr<TAG_COROUTINE, TAG_NIL> current)
		{
			assert(current.type == TAG_COROUTINE || current.type == TAG_NIL);
			ensure_read(per_task_register, __per_task_data);
			auto previous = __per_task_data->__current_coroutine;
			__per_task_data->__current_coroutine = current;
			ensure_write(per_task_register, __per_task_data);
			return previous;
		}

		always_inline static inline per_task *replace_with_new_task()
		{
			ensure_read(per_task_register, __per_task_data);
			per_task *previous = __per_task_data;
			__per_task_data = allocate<per_task>();
			__per_task_data->__current_stack_frame = make_empty_stack_frame();
			__per_task_data->__current_coroutine = nil;
			ensure_write(per_task_register, __per_task_data);
			return previous;
		}

		always_inline static inline per_task *replace_with_existing_task(per_task *existing)
		{
			ensure_read(per_task_register, __per_task_data);
			per_task *previous = __per_task_data;
			__per_task_data = existing;
			ensure_write(per_task_register, __per_task_data);
			return previous;
		}

		#pragma GCC poison per_task __per_task_data __current_stack_frame __current_coroutine // Do not use this except through the macros and functions above
	}

	// Functions and function calls
	inline namespace tagged_types
	{
		template <typename... Args>
		always_inline inline tagged_ptr tagged_ptr::operator()(Args&&... args) const
		{
			return function_call(*this, tuple_create(std::forward<Args>(args)...));
		}
	}

	inline namespace functions
	{
		// Functions
		using native_function = void (*)(tagged_ptr args);

		struct function
		{
			restricted_tagged_ptr<TAG_RAW>          native; // (TAG_RAW, number of total arguments, function pointer)
			restricted_tagged_ptr<TAG_RAW, TAG_NIL> object;
			restricted_tagged_ptr<TAG_TUPLE>        stored_arguments;
		};

		[[noreturn]] always_inline static inline void function_return(tagged_ptr result)
		{
			stack_frame *frame = current_stack_frame().as<stack_frame *>();
			if (!frame->parent)
				__builtin_trap();
			replace_stack_frame(frame->parent);
			__asm__ volatile (
				"movq %[sp], %%rsp;"
				"jmp *%[ra];"
				:: [sp]"D"(frame->stack_address.value()),
				   [ra]"S"(frame->return_address.value()),
				   "a"(result)
				: /* "rax", */ "rbx", "rcx", "rdx", /* "rdi", "rsi", */ "rbp", "r8", "r9", "r10", "r11", "r12", "r13", "r14",
				  zmm_clobbers "memory", "cc"
			);
			__builtin_unreachable();
		}

		[[gnu::noinline, gnu::naked]] static tagged_ptr native_function_call_dispatch(restricted_tagged_ptr<TAG_TUPLE> /* args */, native_function /* target */, stack_frame * /* frame */) // Argument order is deliberate so that args is already in rdi
		{
			__asm__ volatile (
				"popq %c[return_address_offset](%%rdx);"
				"movq %%rsp, %c[stack_address_offset](%%rdx);"
				"movq %[tag_mask], %%rax;"
				"orq %%rax, %c[stack_address_offset](%%rdx);"
				"orq %%rax, %c[return_address_offset](%%rdx);"
				"jmp *%%rsi;"
				:: [return_address_offset]"i"(offsetof(stack_frame, return_address)),
				   [stack_address_offset]"i"(offsetof(stack_frame, stack_address)),
				   [tag_mask]"i"(tag_mask<TAG_RAW>)
				: "rax", "rbx", "rcx", "rdx", "rdi", "rsi", "rbp", "r8", "r9", "r10", "r11", "r12", "r13", "r14",
				  zmm_clobbers "memory", "cc"
			);
		}

		[[gnu::noinline, gnu::naked]] static tagged_ptr native_function_call_object_dispatch(std::uintptr_t /* this */, restricted_tagged_ptr<TAG_TUPLE> /* args */, native_function /* target */, stack_frame * /* frame */) // Argument order is deliberate so that this is already in rdi, and args is already in rsi
		{
			__asm__ volatile (
				"popq %c[return_address_offset](%%rcx);"
				"movq %%rsp, %c[stack_address_offset](%%rcx);"
				"movq %[tag_mask], %%rax;"
				"orq %%rax, %c[stack_address_offset](%%rcx);"
				"orq %%rax, %c[return_address_offset](%%rcx);"
				"jmp *%%rdx;"
				:: [return_address_offset]"i"(offsetof(stack_frame, return_address)),
				   [stack_address_offset]"i"(offsetof(stack_frame, stack_address)),
				   [tag_mask]"i"(tag_mask<TAG_RAW>)
				: "rax", "rbx", "rcx", "rdx", "rdi", "rsi", "rbp", "r8", "r9", "r10", "r11", "r12", "r13", "r14",
				  zmm_clobbers "memory", "cc"
			);
		}

		[[gnu::optimize("no-optimize-sibling-calls")]] always_inline static inline tagged_ptr native_function_call(function *fn, restricted_tagged_ptr<TAG_TUPLE> args)
		{
			assert(args.type == TAG_TUPLE && args.arg == fn->native.arg);
			native_function target = fn->native.as<native_function>();

			stack_frame *frame = allocate<stack_frame>();
			frame->parent = current_stack_frame();
			replace_stack_frame(tagged_ptr { reinterpret_cast<std::uintptr_t>(frame), 0, TAG_RAW });

			if (fn->object)
				return native_function_call_object_dispatch(fn->object.value(), args, target, frame);
			else
				return native_function_call_dispatch(args, target, frame);
		}

		may_inline static inline tagged_ptr function_call(restricted_tagged_ptr<TAG_FUNCTION> func, restricted_tagged_ptr<TAG_TUPLE> args)
		{
			for (;;)
			{
				assert(func.type == TAG_FUNCTION && args.type == TAG_TUPLE);
				volatile function * volatile fn = func.as<function *>();
				if (fn->native.arg > fn->stored_arguments.arg + args.arg)
				{
					// Partially apply function only by making a new struct function.
					function *partial = allocate<function>();
					partial->native = const_cast<function *>(fn)->native;
					partial->stored_arguments = tuple_concat(const_cast<function *>(fn)->stored_arguments, args);
					return tagged_ptr { reinterpret_cast<std::uintptr_t>(partial), func.arg, TAG_FUNCTION };
				}
				else
				{
					// Collected enough arguments to dispatch.
					auto split = tuple_split(args, const_cast<function *>(fn)->native.arg - const_cast<function *>(fn)->stored_arguments.arg);
					tagged_ptr actual_args = tuple_concat(const_cast<function *>(fn)->stored_arguments, split[0]);
					assert(actual_args.arg == fn->native.arg);

					volatile tagged_ptr remaining = split[1];
					barrier();
					tagged_ptr result = native_function_call(const_cast<function *>(fn), actual_args);
					barrier();
					if (remaining.arg == 0)
						return result;

					// Otherwise try applying this again.
					func = result;
					args = const_cast<const tagged_ptr&>(remaining);
				}
			}
		}

		may_inline static inline restricted_tagged_ptr<TAG_FUNCTION> function_create(native_function native, std::uint16_t argc)
		{
			function *fn = allocate<function>();
			fn->native = tagged_ptr { reinterpret_cast<std::uintptr_t>(native), argc, TAG_RAW };
			fn->stored_arguments = tuple_create();
			return core::tagged_ptr { reinterpret_cast<std::uintptr_t>(fn), 0, TAG_FUNCTION };
		}

		template <typename Fn>
		may_inline static inline restricted_tagged_ptr<TAG_FUNCTION> function_create_from_object(Fn&& native, std::uint16_t argc)
		{
			Fn *object = new (allocate<Fn>()) Fn(std::move(native));
			function *fn = allocate<function>();
			fn->native = tagged_ptr { reinterpret_cast<std::uintptr_t>(reinterpret_cast<void *>(&std::remove_reference_t<decltype(*object)>::operator())), argc, TAG_RAW };
			fn->object = tagged_ptr { reinterpret_cast<std::uintptr_t>(object), argc, TAG_RAW };
			fn->stored_arguments = tuple_create();
			return core::tagged_ptr { reinterpret_cast<std::uintptr_t>(fn), 0, TAG_FUNCTION };
		}
	}

	// Coroutines
	inline namespace coroutines
	{
		struct coroutine
		{
			restricted_tagged_ptr<TAG_RAW> saved_context; // Pointer to context
			restricted_tagged_ptr<TAG_RAW> stack_top; // Pointer to top of stack so we can reset
			restricted_tagged_ptr<TAG_COROUTINE, TAG_NIL> replacement; // Resume this coroutine instead if not nil
			restricted_tagged_ptr<TAG_COROUTINE, TAG_NIL> whence; // Where was this coroutine resumed from
			restricted_tagged_ptr<TAG_TUPLE> resume_args; // Arguments for resumption
			restricted_tagged_ptr<TAG_FUNCTION> underlying; // Underlying function
		};

		struct context
		{
			user_regs_struct registers; // Normal registers
			char xsave_area[]; // Big space for XSAVE
		};

		[[gnu::noinline, gnu::naked]] static std::uintptr_t context_save(context * /* state */)
		{
			static_assert(allocator_head_register[0] == 'r' && allocator_head_register[1] == '1' && allocator_head_register[2] == '5', "allocator_head_register changed - please update context_save and context_restore!");
			static_assert(per_task_register[0] == 'r' && per_task_register[1] == '1' && per_task_register[2] == '4', "per_task_register changed - please update context_save and context_restore!");
			__asm__ volatile (
				/* Store flags and registers */
				"pushfq;"
				/* Allocation head should not change "movq %%r15,   (%%rdi);" */
				"movq %%r14,  8(%%rdi);"
				"movq %%r13, 16(%%rdi);"
				"movq %%r12, 24(%%rdi);"
				"movq %%rbp, 32(%%rdi);"
				"movq %%rbx, 40(%%rdi);"
				"movq %%r11, 48(%%rdi);"
				"movq %%r10, 56(%%rdi);"
				"movq %%r9,  64(%%rdi);"
				"movq %%r8,  72(%%rdi);"
				/* No need to save rax properly, we want to set it in restore anyways "movq %%rax, 80(%%rdi);" */
				"movl $1,    80(%%rdi);"
				"movq %%rcx, 88(%%rdi);"
				"movq %%rdx, 96(%%rdi);"
				"movq %%rsi, 104(%%rdi);"
				/* Cannot save rdi here (points to registers) "movq %%rdi, 112(%%rdi);" */
				"popq        144(%%rdi);" /* rflags */
				"movq %%rsp, 152(%%rdi);"
				/* Save rip */
				"movq (%%rsp), %%rax;"
				"movq %%rax, 128(%%rdi);"
				/* Save remaining state */
				"movl $0xffffffff, %%eax;"
				"movl $0xffffffff, %%edx;"
				"xsave64 %c[offset](%%rdi);"
				/* Save rdi */
				"movq %%rdi, 112(%%rdi);"
				/* Set rax to 0 (save successful) */
				"xorl %%eax, %%eax;"
				"ret;"
				:: /* [state] "D" (state), */ [offset] "i" (offsetof(context, xsave_area))
				: "memory", "rax", "rdx"
			);
		}

		[[gnu::noinline, gnu::noreturn, gnu::naked]] static void context_restore(context * /* state */)
		{
			__asm__ volatile (
				/* Restore other state */
				"movl $0xffffffff, %%eax;"
				"movl $0xffffffff, %%edx;"
				"xrstor64 %c[offset](%%rdi);"
				/* Restore stack first, before rip */
				"movq  152(%%rdi), %%rsp;"
				/* Restore rip */
				"movq 128(%%rdi), %%rax;"
				"movq %%rax, (%%rsp);"
				/* Restore registers */
				"pushq 144(%%rdi);" /* rflags */
				/* Cannot restore rdi here (points to registers) "movq  112(%%rdi), %%rdi;" */
				"movq 104(%%rdi), %%rsi;"
				"movq  96(%%rdi),  %%rdx;"
				"movq  88(%%rdi),  %%rcx;"
				"movq  80(%%rdi),  %%rax;"
				"movq  72(%%rdi),  %%r8;"
				"movq  64(%%rdi),  %%r9;"
				"movq  56(%%rdi),  %%r10;"
				"movq  48(%%rdi),  %%r11;"
				"movq  40(%%rdi),  %%rbx;"
				"movq  32(%%rdi),  %%rbp;"
				"movq  24(%%rdi),  %%r12;"
				"movq  16(%%rdi),  %%r13;"
				"movq  8(%%rdi),   %%r14;"
				/* Allocation head should not change "movq  (%%rdi),    %%r15;" */
				/* Finally restore rdi */
				"movq  112(%%rdi), %%rdi;"
				"popfq;"
				/* Cleanup for return */
				"cld;"
				"mfence;"
				"ret;"
				: /* [state] "+D" (state) */
				: [offset] "i" (offsetof(context, xsave_area))
				: "memory", "cc", "rax", "rdx", "rdi" /* And lots of others, but we don't want GCC to know that */
			);
			__builtin_unreachable();
		}

		[[noreturn, gnu::noinline]] static void coroutine_noreturn(restricted_tagged_ptr<TAG_FUNCTION> entry, restricted_tagged_ptr<TAG_TUPLE> args)
		{
			assert(entry.type == TAG_FUNCTION && args.type == TAG_TUPLE);
			function *fn = entry.as<function *>();
			assert(fn->native.arg >= args.arg); // Arguments must be at least as many as required
			std::uintptr_t *stack_top = current_coroutine().as<coroutine *>()->stack_top.as<std::uintptr_t *>();
			current_coroutine().as<coroutine *>()->underlying = entry;
			*stack_top-- = bad_memory; // Leave a bad return address on the stack
			__asm__ volatile (
				"movq %[stack_top], %%rsp;"
				JMP("[native_function_call]")
				:: [stack_top]"r"(stack_top),
				   [native_function_call]"X"(native_function_call),
				   "D"(fn),
				   "S"(args.raw_data())
			);
			__builtin_unreachable();
		}

		may_inline static inline tagged_ptr coroutine_resume_with(restricted_tagged_ptr<TAG_COROUTINE> to, restricted_tagged_ptr<TAG_TUPLE> args, restricted_tagged_ptr<TAG_COROUTINE, TAG_FUNCTION, TAG_NIL> replace_with)
		{
			assert(to.type == TAG_COROUTINE);
			assert(args.type == TAG_TUPLE);
			assert(replace_with.type == TAG_COROUTINE || replace_with.type == TAG_FUNCTION || replace_with.type == TAG_NIL);

			// Save context immediately, so we don't f*ck anything up
			volatile tagged_ptr from = current_coroutine();
			if (from == to)
			{
				/**TODO__asm__ volatile ("int3;");*/
				if (!replace_with)
					return args;
				// Replacement
				from.as<coroutine *>()->replacement = replace_with;
				if (replace_with.type == TAG_COROUTINE)
					return coroutine_resume_with(replace_with, args, core::nil);
				// Replacement with function
				/// XXX: This might be buggy
				coroutine_noreturn(replace_with, args);
			}

			barrier();
			if (from)
			{
				if (context_save(from.as<coroutine *>()->saved_context.as<context *>()))
				{
					barrier();
					return current_coroutine().as<coroutine *>()->resume_args;
				}
				from.as<coroutine *>()->replacement = replace_with;
			}
			barrier();

			coroutine *target = to.as<coroutine *>();
			while (target->replacement.type == TAG_COROUTINE)
				if (target->replacement.type == TAG_COROUTINE)
					target = target->replacement.as<coroutine *>();
			if (target->replacement.type == TAG_FUNCTION)
			{
				target->saved_context.as<context *>()->registers.rip = reinterpret_cast<std::uintptr_t>(coroutine_noreturn); // This means the context_restore never returns to us.
				target->saved_context.as<context *>()->registers.rdi = target->replacement.raw_data();
				target->saved_context.as<context *>()->registers.rsi = args.raw_data();
			}
			else if (target->saved_context.as<context *>()->registers.rip == reinterpret_cast<std::uintptr_t>(coroutine_noreturn)) // Target takes arguments directly via rsi
			{
				target->saved_context.as<context *>()->registers.rsi = args.raw_data();
			}
			target->whence = const_cast<const tagged_ptr&>(from);
			target->resume_args = args;

			barrier();
			context_restore(target->saved_context.as<context *>());
			__builtin_trap();
		}

		template <typename... Args>
		always_inline static inline tagged_ptr coroutine_resume(restricted_tagged_ptr<TAG_COROUTINE> to, Args&&... args)
		{
			return coroutine_resume_with(to, tuple_create(std::forward<Args>(args)...), nil);
		}

		may_inline static inline restricted_tagged_ptr<TAG_COROUTINE> coroutine_create(restricted_tagged_ptr<TAG_FUNCTION> entry)
		{
			assert(entry.type == TAG_FUNCTION);

			volatile coroutine *target = allocate<coroutine>();
			std::uintptr_t allocation = allocate(offsetof(context, xsave_area) + xsave_area_size, 64, 64 - offsetof(context, xsave_area) % 64);
			volatile std::uintptr_t stack = allocate(coroutine_stack_size, 16) + coroutine_stack_size;
			volatile std::uintptr_t fn = entry.raw_data();

			const_cast<coroutine *>(target)->saved_context = tagged_ptr { allocation, 0, TAG_RAW };
			const_cast<coroutine *>(target)->stack_top = tagged_ptr { const_cast<const std::uintptr_t&>(stack), 0, TAG_RAW };
			const_cast<coroutine *>(target)->replacement = nil;
			const_cast<coroutine *>(target)->whence = nil;
			const_cast<coroutine *>(target)->resume_args = empty;
			const_cast<coroutine *>(target)->underlying = entry;

			tagged_ptr result { reinterpret_cast<std::uintptr_t>(target), 0, TAG_COROUTINE };

			volatile auto previous = replace_with_new_task();
			replace_coroutine(result);
			assert(!context_save(target->saved_context.as<context *>()));
			barrier();
			replace_with_existing_task(previous);

			const_cast<coroutine *>(target)->saved_context.as<context *>()->registers.rip = reinterpret_cast<std::uintptr_t>(coroutine_noreturn);
			const_cast<coroutine *>(target)->saved_context.as<context *>()->registers.rdi = const_cast<const std::uintptr_t&>(fn);
			const_cast<coroutine *>(target)->saved_context.as<context *>()->registers.rsi = empty.raw_data();
			const_cast<coroutine *>(target)->saved_context.as<context *>()->registers.rsp = const_cast<const std::uintptr_t&>(stack);

			return result;
		}

		always_inline static inline restricted_tagged_ptr<TAG_COROUTINE, TAG_NIL> coroutine_whence()
		{
			if (current_coroutine().type == TAG_COROUTINE)
				return current_coroutine().as<coroutine *>()->whence;
			else
				return nil;
		}

		always_inline static inline restricted_tagged_ptr<TAG_FUNCTION> current_coroutine_function()
		{
			if (current_coroutine().type == TAG_COROUTINE)
				return current_coroutine().as<coroutine *>()->underlying;
			else
				return nil;
		}
	}

	// Integer stuff
	inline namespace integer_ops
	{
		// Integers are by default u48, don't really care about implementing bigints if I don't need them for the crypto...
		always_inline constexpr static inline restricted_tagged_ptr<TAG_INT> __int_create(std::uintptr_t value, std::uint16_t arg)
		{
			std::uintptr_t actual = static_cast<std::uintptr_t>(value) & ((static_cast<std::uintptr_t>(1) << (tagged_ptr_value_bytes * 8)) - 1);
			return tagged_ptr { actual, arg, TAG_INT };
		}

		template <typename T>
		may_inline constexpr static inline std::enable_if_t<(sizeof(T) < tagged_ptr_value_bytes) && std::is_integral_v<T>, restricted_tagged_ptr<TAG_INT>> int_create(T value)
		{
			if constexpr (std::is_signed_v<T>)
				return __int_create(static_cast<std::uintptr_t>(static_cast<std::intptr_t>(value)), 0); // Sign-extend signed values
			else
				return __int_create(static_cast<std::uintptr_t>(value), 0);
		}

		template <typename T>
		may_inline static inline T int_value(restricted_tagged_ptr<TAG_INT> wrapped)
		{
			static_assert(std::is_integral_v<T>, "int_value: Type is not an integer type");
			/// XXX: Mind the truncation issue here, deal with all the bigint stuff
			assert(wrapped.type == TAG_INT);
			assert(wrapped.arg == 0); // Leave space for future bigint extensions
			if constexpr (std::is_signed_v<T>)
			{
				std::uintptr_t sign = (wrapped.value() >> (tagged_ptr_value_bytes * 8 - 1))
					? static_cast<std::uintptr_t>(-1) & (~((static_cast<std::uintptr_t>(1) << (tagged_ptr_value_bytes * 8)) - 1))
					: static_cast<std::uintptr_t>(0);
				return static_cast<T>(static_cast<std::intptr_t>(wrapped.value() | sign));
			}
			else
				return static_cast<T>(wrapped.value());
		}

		// Thanks to two's complement we don't mind signedness issues so much
		#define int_binary_operator_wrapper(name, op) \
			may_inline static inline restricted_tagged_ptr<TAG_INT> name(restricted_tagged_ptr<TAG_INT> a, restricted_tagged_ptr<TAG_INT> b) \
			{ \
				return __int_create(int_value<std::uintptr_t>(a) op int_value<std::uintptr_t>(b), 0); \
			}
		#define int_unary_operator_wrapper(name, op) \
			may_inline static inline restricted_tagged_ptr<TAG_INT> name(restricted_tagged_ptr<TAG_INT> a) \
			{ \
				return __int_create(op int_value<std::uintptr_t>(a), 0); \
			}
		int_binary_operator_wrapper(int_add, +)
		int_binary_operator_wrapper(int_sub, -)
		int_binary_operator_wrapper(int_mul, *)
		int_binary_operator_wrapper(int_div, /
		) /* Newline, because the / messes my editor up */
		int_binary_operator_wrapper(int_mod, %)
		int_binary_operator_wrapper(int_and, &)
		int_binary_operator_wrapper(int_or,  |)
		int_binary_operator_wrapper(int_xor, ^)
		int_binary_operator_wrapper(int_shl, <<)
		int_binary_operator_wrapper(int_shr, >>)
		int_unary_operator_wrapper(int_neg, -)
		int_unary_operator_wrapper(int_not, ~)

		namespace literals
		{
			always_inline static inline core::tagged_ptr operator "" _t(unsigned long long value)
			{
				/// XXX: Handle big integers here
				return core::__int_create(value, 0);
			}
		}
	}

	// String stuff
	inline namespace string_ops
	{
		always_inline static inline tagged_ptr string_create(const char *data)
		{
			return tagged_ptr { reinterpret_cast<std::uintptr_t>(data), 0, TAG_STRING };
		}

		may_inline static inline tagged_ptr string_intern(const char *data)
		{
			std::size_t size = std::strlen(data) + 1;
			std::uintptr_t copy = allocate(size);
			memcpy(reinterpret_cast<char *>(copy), data, size);
			return tagged_ptr { copy, 1, TAG_STRING };
		}

		may_inline static inline tagged_ptr string_intern(const char *data, std::size_t size)
		{
			std::uintptr_t copy = allocate(size + 1);
			memcpy(reinterpret_cast<char *>(copy), data, size);
			// The memory is already zeroed, so no need for extra null-termination
			return tagged_ptr { copy, 1, TAG_STRING };
		}

		may_inline static inline tagged_ptr string_intern(std::size_t size)
		{
			std::uintptr_t copy = allocate(size + 1);
			return tagged_ptr { copy, 1, TAG_STRING };
		}

		always_inline static inline const char *string_value(tagged_ptr value)
		{
			assert(value.type == TAG_STRING);
			return reinterpret_cast<const char *>(value.value()); // If you are sure you can modify this, const_cast is allowed.
		}

	}

	// Initialization routines
	inline namespace initialization
	{
		[[gnu::noinline, gnu::naked]] static void stack_pivot()
		{
			// This used to pivot the stack for allocations - now it just makes some space for main and keeps going
			__asm__ volatile (
				"leaq -%c[offset](%%rsp), %%" allocator_head_register ";"
				"ret;"
				:: [offset]"i"(coroutine_stack_size + main_extra_stack_size)
			);
		}

		// This would be a lot cleaner with STL stuff, but that always makes the assembly so ugly...
		using initializer_function = tagged_ptr (*)();
		volatile static initializer_function init_hooks[init_hook_limit];
		volatile static std::size_t init_hook_count = 0;
		static bool is_initialized = false;

		may_inline static inline void init()
		{
			// Calling this function is required before calling any other functions
			// (except for the creation of lazy objects, which exist expressly for
			// this purpose)
			// Note that you should _not_ call this function prior to main, because
			// it makes use of register variables that we cannot assume to remain
			// unchanged by the precompiled initialization code.

#if defined(required_stack_size)
			rlimit limit;
			if (getrlimit(RLIMIT_STACK, &limit) == 0)
			{
				if (limit.rlim_cur < required_stack_size)
				{
					limit.rlim_cur = required_stack_size;
					setrlimit(RLIMIT_STACK, &limit);
				}
			}
#endif
			stack_pivot();
			replace_with_new_task();

			is_initialized = true;
			while (init_hook_count)
				init_hooks[--init_hook_count]();
		}

		may_inline static inline tagged_ptr register_init_hook(initializer_function fn)
		{
			if (is_initialized)
				return fn();
			else
			{
				assert(init_hook_count < init_hook_limit);
				init_hooks[init_hook_count++] = fn;
				return nil;
			}
		}
	}

	// Miscellaneous utilities
	inline namespace miscellaneous
	{
		template <typename Fn> struct argument_count;
		template <typename R, typename... Args> struct argument_count<R(Args...)> : std::integral_constant<std::size_t, sizeof...(Args)> {};
		template <typename R, typename... Args> struct argument_count<R(*)(Args...)> : std::integral_constant<std::size_t, sizeof...(Args)> {};
		template <typename C, typename R, typename... Args> struct argument_count<R(C::*)(Args...)> : std::integral_constant<std::size_t, sizeof...(Args)> {};
		template <typename C, typename R, typename... Args> struct argument_count<R(C::*)(Args...) const> : std::integral_constant<std::size_t, sizeof...(Args)> {};
		/// XXX: If necessary, add extra specializations here (for volatile, noexcept, etc.)

		template <typename Fn, std::size_t... Args>
		always_inline static inline decltype(auto) __apply_unpack(Fn&& fn, restricted_tagged_ptr<TAG_TUPLE> arg_tuple, std::integer_sequence<std::size_t, Args...>)
		{
			(void) arg_tuple; // Avoid the warning if sizeof...(Args) == 0.
			return fn(arg_tuple[Args]...);
		}

		template <std::size_t Argc, typename Fn>
		always_inline static inline decltype(auto) apply_unpack(Fn&& fn, restricted_tagged_ptr<TAG_TUPLE> arg_tuple)
		{
			assert(arg_tuple.type == TAG_TUPLE);
			assert(arg_tuple.arg == Argc);
			return __apply_unpack(std::forward<Fn>(fn), arg_tuple, std::make_index_sequence<Argc>{});
		}
	}
}

using namespace core::literals;

#define __name_native_wrapper(name) __nw_##name
#define __name_native_impl(name) __ni_##name

#define __validate_name_present(name, ...)
#define __argc_of(...) core::argument_count<void(__VA_ARGS__)>::value

#define __define_object(constructor, terminator, name, ...) \
	may_inline static inline void __name_native_impl(name)(__VA_ARGS__); \
	[[gnu::noinline]] static void __name_native_wrapper(name)(core::tagged_ptr args) { core::apply_unpack<__argc_of(__VA_ARGS__)>(__name_native_impl(name), args); terminator; } \
	static core::tagged_ptr name = core::register_init_hook(+[] { return name = constructor(__name_native_wrapper(name), __argc_of(__VA_ARGS__)); }); \
	may_inline static inline void __name_native_impl(name)(__VA_ARGS__)

// ... should really be 'name, ...', but we need to handle the case that ... = '' gracefully, without extra commas (and without __VA_OPT__)
#define __coroutine_create(...) core::coroutine_create(core::function_create(__VA_ARGS__))
#define function(...) __validate_name_present(__VA_ARGS__) __define_object(core::function_create, core::function_return(core::nil), __VA_ARGS__)
#define coroutine(...) __validate_name_present(__VA_ARGS__) __define_object(__coroutine_create, core::invalid_function(), __VA_ARGS__)

#define lambda(...) \
	[](auto native_lambda) -> core::restricted_tagged_ptr<core::TAG_FUNCTION> \
	{ \
		auto wrapper = [native_lambda](core::tagged_ptr args) mutable \
		{ \
			core::apply_unpack<core::argument_count<decltype(&decltype(native_lambda)::operator())>::value>(native_lambda, args); \
			core::function_return(core::nil); \
		}; \
		return core::function_create_from_object(std::move(wrapper), core::argument_count<decltype(&decltype(native_lambda)::operator())>::value); \
	}(__VA_ARGS__)
#define lfn(var, ...) lambda([](core::tagged_ptr var){ core::function_return( __VA_ARGS__ ); })


// Prevent people from doing stupid things with normal return.
#define UNSAFE_I_KNOW_WHAT_I_AM_DOING_LET_ME_RETURN return
#pragma GCC poison return

// Standard library
#include "stdlib.tcc"

// User program
#include "main.tcc"

// Main function that just collects argv and resumes the main coroutine, whatever that will be
int main(int argc, char *argv[])
{
	core::init();

	core::tagged_ptr argv_list = stdlib::list_create();
	for (int i = argc - 1; i >= 0; --i)
		argv_list = stdlib::prepend(argv_list, core::string_create(argv[i]));

	core::coroutine_resume(main_coroutine, argv_list);
}
