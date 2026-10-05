from sage.all import Integer, Zmod, gcd, inverse_mod, randint, random_matrix, vector
import os
import sys

real_flag = b"{r0s3s_4re_sp1ky,_vi0l3ts_4re_n0t,_1_h0pe_y0u're_no_b0t"
fake_flag = b"{i_4m_surpr153d_th4t_4ny0n3_w0uld_st1ll_f4ll_f0r_th1s!!"

n = 55
R = Zmod(256)

real_coeff = 0x504
fake_coeff = 0x539

assert len(real_flag) == len(fake_flag) == n

def rand_vec():
    return vector(R, [randint(0, 255) for _ in range(n)])

def rand_invertible_matrix():
    while True:
        M = random_matrix(R, n, n)
        if gcd(M.det(), 256) == 1:
            return M

def to_vec(bs):
    return vector(R, list(bs))

x_real = to_vec(real_flag)
x_fake = to_vec(fake_flag)

A = rand_invertible_matrix()
d = x_fake - x_real
coeff_gap = Integer((fake_coeff - real_coeff) % 256)
assert gcd(coeff_gap, 256) == 1

while True:
    v = rand_vec()
    s = v.dot_product(x_fake)
    if gcd(Integer(s), 256) == 1:
        break

u = (- inverse_mod(coeff_gap * Integer(s), 256)) * (A * d)
D = u.column() * v.row()

b = A * x_real
M = A - D * real_coeff

assert (M + D * real_coeff) * x_real == b
assert (M + D * fake_coeff) * x_fake == b

assert (M + D * real_coeff) * x_fake != b
assert (M + D * fake_coeff) * x_real != b

data = bytearray(os.urandom(8192))
assert len(data) > n * n + 10 * n

coeffs_offset = randint(n * 3, len(data) - n * n - n * 3)
begin_range = (0, coeffs_offset)
end_range = (coeffs_offset + n * n, len(data) - 1)

u_offset = randint(n, coeffs_offset - n)
v_offset = randint(coeffs_offset + n * n, len(data) - n)

result_offset = randint(0, u_offset - n)

data[coeffs_offset:coeffs_offset + n * n] = bytes(int(e) for e in M.list())
data[u_offset:u_offset + n] = bytes(int(e) for e in u.list())
data[v_offset:v_offset + n] = bytes(int(e) for e in v.list())
data[result_offset:result_offset + n] = bytes(int(e) for e in b.list())

offsets = {
    "s1_coeffs": coeffs_offset,
    "s1_result": result_offset,
    "s1_offset_u": u_offset,
    "s1_offset_v": v_offset,
    "s1_coeffs_fake": randint(0, len(data) - n * n),
    "s1_result_fake": randint(0, len(data) - n),
    "s1_offset_u_fake": randint(0, len(data) - n),
    "s1_offset_v_fake": randint(0, len(data) - n),
}

labels = {}
for k, v in offsets.items():
    if v not in labels:
        labels[v] = []
    labels[v].append(k)

with open(sys.argv[1], "w") as out:
    out.write(".pushsection .rodata\n")
    pos = 0
    for p in sorted(labels):
        if p > pos:
            out.write(".byte " + ", ".join(hex(byte) for byte in data[pos:p]) + "\n")
            pos = p
        for l in labels[p]:
            out.write(l + ":\n")
    if pos < len(data):
        out.write(".byte " + ", ".join(hex(byte) for byte in data[pos:]) + "\n")
    out.write(".popsection\n")
