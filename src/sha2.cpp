#include "sha2.hpp"
/*
 * Initialize array of round constants:
 * (first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311):
 */
static const uint32_t k[] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};
SHA2::SHA2(QObject *parent) : QObject(parent)
{
   STRING_VECTORS[0] =  {
       "",
       "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
   };
   STRING_VECTORS[1] = {
       "abc",
       "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
   };
   STRING_VECTORS[2] = 	{
       "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
       "a8ae6e6ee929abea3afcfc5258c8ccd6f85273e0d4626d26c7279f3250f77c8e"
   };
   STRING_VECTORS[3] =	{
       "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
       "057ee79ece0b9a849552ab8d3c335fe9a5f1c46ef5f1d9b190c295728628299c"
   };
   STRING_VECTORS[4] = 	{
       "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0",
       "2a6ad82f3620d3ebe9d678c812ae12312699d673240d5be8fac0910a70000d93"
   };
   STRING_VECTORS[5] =	{
       "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
       "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
   };
   STRING_VECTORS[6] = 	{
       "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
       "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
       "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"
   };
   data1[0] = { 0xbd };
   data2[0] = { 0xc9 };
   data2[1] = { 0x8c };
   data2[2] = { 0x8e };
   data2[3] = { 0x55 };
   vectors[0] ={
       data1,
       sizeof data1,
       "68325720aabd7c82f30f554b313d0570c95accbb7dc4b5aae11204c08ffe732b"
   };
   vectors[1] =	{
       data2,
       sizeof data2,
       "7abc22c0ae5af26ce93dbb94433a0e0b2e119d014f8e7f65bd56c61ccccd9504"
   };
   vectors[2] =	{
       data7,
       55,
       "02779466cdec163811d078815c633f21901413081449002f24aa3e80f0b88ef7"
   };
   vectors[3] =	{
       data7,
       56,
       "d4817aa5497628e7c77e6b606107042bbba3130888c5f47a375e6179be789fbb"
   };
   vectors[4] =	{
       data7,
       57,
       "65a16cb7861335d5ace3c60718b5052e44660726da4cd13bb745381b235a1785"
   };
   vectors[5] =	{
       data7,
       64,
       "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b"
   };
   vectors[6] =	{
       data7,
       sizeof data7,
       "541b3e9daa09b20bf85fa273e5cbd3e80185aa4ec298e765db87742b70138a53"
   };
   vectors[7] =	{
       data8,
       sizeof data8,
       "c2e686823489ced2017f6059b8b239318b6364f6dcd835d0a519105a1eadd6e4"
   };
   vectors[8] =	{
       data9,
       sizeof data9,
       "f4d62ddec0f3dd90ea1380fa16a5ff8dc4c54b21740650f24afc4120903552b0"
   };
   vectors[9] =	{
       NULL,
       1000000,
       "d29751f2649b32ff572b5e0a9f541ea660a50f94ff0beedfb0b692b924cc8025"
   };
   vectors[10] =	{
       NULL,
       SIZEOF_DATA11,
       "15a1868c12cc53951e182344277447cd0979536badcc512ad24c67e9b2d4f3dd"
   };
   vectors[11] =	{
       NULL,
       SIZEOF_DATA12,
       "461c19a93bd4344f9215f5ec64357090342bc66b15a148317d276e31cbc20b53"
   };
   vectors[12] =	{
       NULL,
       SIZEOF_DATA13,
       "c23ce8a7895f4b21ec0daf37920ac0a262a220045a03eb2dfed48ef9b05aabea"
   };
   size_t i;
   for (i = 0; i < (sizeof STRING_VECTORS / sizeof (struct string_vector)); i++) {
       const struct string_vector *vector = &STRING_VECTORS[i];
       if (string_test(vector->input, vector->output)) {
           qDebug()<<__LINE__ << __FUNCTION__ << "Input " << vector->input;
           qDebug()<<__LINE__ << __FUNCTION__ << "Output " << vector->output;
       }

   }
   construct_binary_messages();
   for (i = 0; i < (sizeof vectors / sizeof (struct vector)); i++) {
           const struct vector *vector = &vectors[i];
           if (test(vector->input, vector->input_len, vector->output))
           {
               destruct_binary_messages();
               qDebug()<<__LINE__ << __FUNCTION__ << "Input " << vector->input;
               qDebug()<<__LINE__ << __FUNCTION__ << "Output " << vector->output;
           }
       }
   destruct_binary_messages();
}

uint32_t SHA2::right_rot(uint32_t value, unsigned int count)
{
    /*
     * Defined behaviour in standard C for all count where 0 < count < 32,
     * which is what we need here.
     */
    return value >> count | value << (32 - count);
}

void SHA2::init_buf_state(struct buffer_state * state, const uint8_t * input, size_t len)
{
    state->p = input;
    state->len = len;
    state->total_len = len;
    state->single_one_delivered = 0;
    state->total_len_delivered = 0;
}

/* Return value: bool */
int SHA2::calc_chunk(uint8_t chunk[CHUNK_SIZE], struct buffer_state * state)
{
    size_t space_in_chunk;

    if (state->total_len_delivered) {
        return 0;
    }

    if (state->len >= CHUNK_SIZE) {
        memcpy(chunk, state->p, CHUNK_SIZE);
        state->p += CHUNK_SIZE;
        state->len -= CHUNK_SIZE;
        return 1;
    }

    memcpy(chunk, state->p, state->len);
    chunk += state->len;
    space_in_chunk = CHUNK_SIZE - state->len;
    state->p += state->len;
    state->len = 0;

    /* If we are here, space_in_chunk is one at minimum. */
    if (!state->single_one_delivered) {
        *chunk++ = 0x80;
        space_in_chunk -= 1;
        state->single_one_delivered = 1;
    }

    /*
     * Now:
     * - either there is enough space left for the total length, and we can conclude,
     * - or there is too little space left, and we have to pad the rest of this chunk with zeroes.
     * In the latter case, we will conclude at the next invokation of this function.
     */
    if (space_in_chunk >= TOTAL_LEN_LEN) {
        const size_t left = space_in_chunk - TOTAL_LEN_LEN;
        size_t len = state->total_len;
        int i;
        memset(chunk, 0x00, left);
        chunk += left;

        /* Storing of len * 8 as a big endian 64-bit without overflow. */
        chunk[7] = (uint8_t) (len << 3);
        len >>= 5;
        for (i = 6; i >= 0; i--) {
            chunk[i] = (uint8_t) len;
            len >>= 8;
        }
        state->total_len_delivered = 1;
    } else {
        memset(chunk, 0x00, space_in_chunk);
    }

    return 1;
}
/*
 * Limitations:
 * - Since input is a pointer in RAM, the data to hash should be in RAM, which could be a problem
 *   for large data sizes.
 * - SHA algorithms theoretically operate on bit strings. However, this implementation has no support
 *   for bit string lengths that are not multiples of eight, and it really operates on arrays of bytes.
 *   In particular, the len parameter is a number of bytes.
 */
void SHA2::calc_sha_256(uint8_t hash[32], const uint8_t * input, size_t len)
{
    /*
     * Note 1: All integers (expect indexes) are 32-bit unsigned integers and addition is calculated modulo 2^32.
     * Note 2: For each round, there is one round constant k[i] and one entry in the message schedule array w[i], 0 = i = 63
     * Note 3: The compression function uses 8 working variables, a through h
     * Note 4: Big-endian convention is used when expressing the constants in this pseudocode,
     *     and when parsing message block data from bytes to words, for example,
     *     the first word of the input message "abc" after padding is 0x61626380
     */

    /*
     * Initialize hash values:
     * (first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19):
     */
    uint32_t h[] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
    unsigned i, j;

    /* 512-bit chunks is what we will operate on. */
    uint8_t chunk[64];

    struct buffer_state state;

    init_buf_state(&state, input, len);

    while (calc_chunk(chunk, &state)) {
        uint32_t ah[8];

        const uint8_t *p = chunk;

        /* Initialize working variables to current hash value: */
        for (i = 0; i < 8; i++)
            ah[i] = h[i];

        /* Compression function main loop: */
        for (i = 0; i < 4; i++) {
            /*
             * The w-array is really w[64], but since we only need
             * 16 of them at a time, we save stack by calculating
             * 16 at a time.
             *
             * This optimization was not there initially and the
             * rest of the comments about w[64] are kept in their
             * initial state.
             */

            /*
             * create a 64-entry message schedule array w[0..63] of 32-bit words
             * (The initial values in w[0..63] don't matter, so many implementations zero them here)
             * copy chunk into first 16 words w[0..15] of the message schedule array
             */
            uint32_t w[16];

            for (j = 0; j < 16; j++) {
                if (i == 0) {
                    w[j] = (uint32_t) p[0] << 24 | (uint32_t) p[1] << 16 |
                        (uint32_t) p[2] << 8 | (uint32_t) p[3];
                    p += 4;
                } else {
                    /* Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array: */
                    const uint32_t s0 = right_rot(w[(j + 1) & 0xf], 7) ^ right_rot(w[(j + 1) & 0xf], 18) ^ (w[(j + 1) & 0xf] >> 3);
                    const uint32_t s1 = right_rot(w[(j + 14) & 0xf], 17) ^ right_rot(w[(j + 14) & 0xf], 19) ^ (w[(j + 14) & 0xf] >> 10);
                    w[j] = w[j] + s0 + w[(j + 9) & 0xf] + s1;
                }
                const uint32_t s1 = right_rot(ah[4], 6) ^ right_rot(ah[4], 11) ^ right_rot(ah[4], 25);
                const uint32_t ch = (ah[4] & ah[5]) ^ (~ah[4] & ah[6]);
                const uint32_t temp1 = ah[7] + s1 + ch + k[i << 4 | j] + w[j];
                const uint32_t s0 = right_rot(ah[0], 2) ^ right_rot(ah[0], 13) ^ right_rot(ah[0], 22);
                const uint32_t maj = (ah[0] & ah[1]) ^ (ah[0] & ah[2]) ^ (ah[1] & ah[2]);
                const uint32_t temp2 = s0 + maj;

                ah[7] = ah[6];
                ah[6] = ah[5];
                ah[5] = ah[4];
                ah[4] = ah[3] + temp1;
                ah[3] = ah[2];
                ah[2] = ah[1];
                ah[1] = ah[0];
                ah[0] = temp1 + temp2;
            }
        }

        /* Add the compressed chunk to the current hash value: */
        for (i = 0; i < 8; i++)
            h[i] += ah[i];
    }

    /* Produce the final hash value (big-endian): */
    for (i = 0, j = 0; i < 8; i++)
    {
        hash[j++] = (uint8_t) (h[i] >> 24);
        hash[j++] = (uint8_t) (h[i] >> 16);
        hash[j++] = (uint8_t) (h[i] >> 8);
        hash[j++] = (uint8_t) h[i];
    }
}
void SHA2::construct_binary_messages(void)
{
    memset(data7, 0x00, sizeof data7);
    memset(data8, 0x41, sizeof data8);
    memset(data9, 0x55, sizeof data9);
    /*
     * Heap allocation as a workaround for some linkers not liking
     * large BSS segments.
     */
    data11 = (uint8_t *)malloc(SIZEOF_DATA11);
    data12 = (uint8_t *)malloc(SIZEOF_DATA12);
    data13 = (uint8_t *)malloc(SIZEOF_DATA13);
    memset(data11, 0x5a, SIZEOF_DATA11);
    memset(data12, 0x00, SIZEOF_DATA12);
    memset(data13, 0x42, SIZEOF_DATA13);
    vectors[9].input = data12;
    vectors[10].input = data11;
    vectors[11].input = data12;
    vectors[12].input = data13;
}
void SHA2::destruct_binary_messages(void)
{
    free(data11);
    free(data12);
    free(data13);
}
void SHA2::hash_to_string(char string[65], const uint8_t hash[32])
{
   size_t i;
   for (i = 0; i < 32; i++) {
       string += sprintf(string, "%02x", hash[i]);
   }
}
int SHA2::string_test(const char input[], const char output[])
{
    uint8_t hash[32];
    char hash_string[65];
    calc_sha_256(hash, (uint8_t *)input, strlen(input));
    hash_to_string(hash_string, hash);
    printf("input: %s\n", input);
    printf("hash : %s\n", hash_string);
    if (strcmp(output, hash_string)) {
        printf("FAILURE!\n\n");
        return 1;
    } else {
        printf("SUCCESS!\n\n");
        return 0;
    }
}
/*
 * Limitation:
 * - The variable input_len will be truncated to its LONG_BIT least
 * significant bits in the print output. This will never be a problem
 * for values that in practice are less than 2^32 - 1. Rationale: ANSI
 * C-compatibility and keeping it simple.
 */
int SHA2::test(const uint8_t * input, size_t input_len, const char output[])
{
    uint8_t hash[32];
    char hash_string[65];
    calc_sha_256(hash, input, input_len);
    hash_to_string(hash_string, hash);
    printf("input starts with 0x%02x, length %lu\n", *input, (unsigned long) input_len);
    printf("hash : %s\n", hash_string);
    if (strcmp(output, hash_string)) {
        printf("FAILURE!\n\n");
        return 1;
    } else {
        printf("SUCCESS!\n\n");
        return 0;
    }
}
