#include <asm/ldt.h>
#include <stdlib.h>

extern const struct user_desc __lemonade_start;
extern const struct user_desc __lemonade_end;

__attribute__((constructor)) static void initialize_segments(void) {
    for (const struct user_desc *desc = &__lemonade_start; desc != &__lemonade_end; ++desc) {
        long eax = 123 /* SYS_modify_ldt */;
        __asm__ volatile (
            "int $0x80"
            : "+&a"(eax)
            : "b"(17 /* New "set" operation */),
              "c"(desc),
              "d"(sizeof(*desc))
        );
        if (eax)
            _Exit(eax);
    }
}
