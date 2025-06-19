#include <alloca.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const int grid[] = {
    0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0,
    0, 1, 1, 2, 2, 1, 0, 2, 2, 0, 0, 1, 1, 0, 2,
    1, 1, 0, 0, 2, 2, 0, 0, 2, 2, 0, 3, 1, 0, 2,
    1, 2, 2, 0, 0, 2, 3, 0, 0, 2, 3, 3, 3, 2, 2,
    0, 0, 2, 2, 0, 3, 3, 3, 3, 1, 0, 0, 3, 2, 1,
    2, 0, 0, 2, 1, 1, 0, 2, 2, 1, 1, 0, 0, 1, 1,
    2, 2, 0, 1, 1, 0, 0, 0, 2, 2, 1, 1, 0, 2, 1,
    1, 2, 2, 1, 2, 2, 0, 1, 1, 2, 3, 3, 3, 3, 1,
    1, 3, 3, 0, 0, 2, 2, 3, 1, 1, 3, 1, 1, 0, 0,
    1, 1, 3, 3, 0, 0, 2, 3, 3, 1, 0, 0, 1, 1, 0,
    1, 0, 0, 3, 2, 0, 3, 3, 2, 2, 2, 0, 0, 1, 0,
    2, 2, 0, 0, 2, 2, 1, 1, 2, 2, 1, 1, 0, 2, 3,
    2, 2, 2, 0, 2, 1, 1, 0, 0, 3, 3, 1, 1, 2, 3,
    0, 0, 3, 3, 2, 1, 2, 2, 0, 0, 3, 3, 1, 3, 3,
    3, 0, 0, 3, 3, 0, 0, 2, 2, 0, 3, 0, 0, 3, 1,
    3, 3, 0, 1, 3, 2, 0, 0, 2, 1, 2, 2, 0, 0, 1,
    0, 3, 3, 1, 1, 2, 2, 0, 1, 1, 1, 2, 2, 0, 1,
    0, 1, 2, 2, 1, 1, 2, 2, 3, 1, 0, 0, 2, 1, 1,
    0, 1, 1, 2, 2, 0, 0, 0, 3, 2, 2, 0, 0, 0, 3,
    0, 0, 1, 1, 2, 0, 0, 3, 3, 3, 2, 3, 3, 3, 3,
};
static int values[] = {
    2, 3, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 5, 0, 0, 0, 2, 0, 5, 2, 0, 1, 5, 0,
    0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 1, 5, 0, 0, 0, 0, 0, 4, 0,
    0, 1, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    3, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 1, 0, 0, 0, 0, 5, 0, 0, 0, 4, 2, 0, 3, 0,
    0, 0, 0, 0, 5, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    4, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 3, 0, 0, 4, 0, 0, 0, 0, 0, 0, 3, 0, 0, 5,
    0, 0, 0, 0, 0, 2, 0, 0, 0, 5, 0, 0, 0, 0, 0,
    0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 1,
    0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 2, 0, 3, 0,
    0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    4, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 3, 0, 0,
    0, 5, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 3,
};

const int width = 15;
const int height = 20;

// The (unobfuscated, so far) Suguru solution checker.
[[gnu::noinline, lemonade]] static int check_suguru(void) {
    int error = 0;
    // Step 1: No same values next to each other, even diagonally.
    for (int r = 0; r < height; ++r)
        for (int c = 0; c < width; ++c)
            for (int dr = r > 0 ? -1 : 0; dr < (r < height - 1) ? 1 : 0; ++dr)
                for (int dc = c > 0 ? -1 : 0; dc < (c < width - 1) ? 1 : 0; ++dc)
                    if (dr || dc)
                        error |= values[(r + dr) * width + c + dc] == values[r * width + c];

    // Step 2: Each field must contain the values from 1 to N.
    typedef struct { int r, c; } pos_t;
    pos_t *queue = alloca(width * height * sizeof(*queue));
    char *queued = alloca(width * height * sizeof(*queued));
    for (size_t i = 0; i < width * height * sizeof(*queued); ++i)
        queued[i] = 0; // -fno-builtin: no memset here.
    for (int r = 0; r < height; ++r) {
        for (int c = 0; c < width; ++c) {
            if (queued[r * width + c])
                continue;

            unsigned size = 0;
            unsigned long long acc = 0;

            // Flood-fill the field.
            int head = 0, tail = 0;
            queue[tail++] = (pos_t) { .r = r, .c = c };
            queued[r * width + c] = 1;
            while (head < tail) {
                pos_t cur = queue[head++];
                int color = grid[cur.r * width + cur.c];
                int value = values[cur.r * width + cur.c];
                int oob = (value <= 0 || value >= (int) sizeof(acc) * CHAR_BIT);
                error |= oob;
                acc |= 1ull << (oob ? 0 : (value - 1));
                ++size;

                // Check non-diagonal neighbors only, here.
                for (int d = -1; d <= 1; d += 2) {
                    if (cur.r + d >= 0 && cur.r + d < height && grid[(cur.r + d) * width + cur.c] == color && !queued[(cur.r + d) * width + cur.c]) {
                        queue[tail++] = (pos_t) { .r = cur.r + d, .c = cur.c };
                        queued[(cur.r + d) * width + cur.c] = 1;
                    }
                    if (cur.c + d >= 0 && cur.c + d < width && grid[cur.r * width + cur.c + d] == color && !queued[cur.r * width + cur.c + d]) {
                        queue[tail++] = (pos_t) { .r = cur.r, .c = cur.c + d };
                        queued[cur.r * width + cur.c + d] = 1;
                    }
                }
            }

            int oob = (size >= (int) sizeof(acc) * CHAR_BIT);
            error |= oob;
            size = oob ? 0 : size;
            error |= acc != ((1ull << size) - 1);
        }
    }

    return !error;
}

char flag[] = {
#embed "encrypted-flag.bin"
    , 0x00
};

int main(int argc, char *argv[]) {
    if (argc != 2)
        goto sad;

    char *cursor = argv[1];
    for (int i = 0; i < width * height; ++i) {
        if (!values[i]) {
            if (*cursor >= '1' && *cursor <= '5')
                values[i] = *cursor++ - '0';
            else
                goto sad;
        }
    }
    if (*cursor)
        goto sad;


    if (!check_suguru())
        goto sad;


    uint8_t S[256];
    for (int i = 0; i < 256; ++i)
        S[i] = i;

    int x = 0;
    uint8_t t;
    for (int i = 0; i < 256; ++i) {
        x = (x + S[i] + argv[1][i % strlen(argv[1])]) & 0xff;
        t = S[i];
        S[i] = S[x];
        S[x] = t;
    }

    x = 0;
    int y = 0;
    for (int i = 0; i < sizeof(flag) - 1; ++i) {
        x = (x + 1) & 0xff;
        y = (y + S[x]) & 0xff;
        t = S[x];
        S[x] = S[y];
        S[y] = t;
        flag[i] ^= S[(S[x] + S[y]) & 0xff];
    }

    printf("%s\n", flag);
    return EXIT_SUCCESS;

sad:
    printf(":(\n");
    return EXIT_FAILURE;
}
