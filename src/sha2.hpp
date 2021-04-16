#ifndef SHA2_HPP
#define SHA2_HPP
#define CHUNK_SIZE 64
#define TOTAL_LEN_LEN 8
#define LARGE_MESSAGES 1
#define SIZEOF_DATA11 536870912
#define SIZEOF_DATA12 1090519040
#define SIZEOF_DATA13 1610612798
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <QObject>
#include <QDebug>

class SHA2 : public QObject
{
    Q_OBJECT
public:
    explicit SHA2(QObject *parent = nullptr);


/*
 * ABOUT bool: this file does not use bool in order to be as pre-C99 compatible as possible.
 */

/*
 * Comments from pseudo-code at https://en.wikipedia.org/wiki/SHA-2 are reproduced here.
 * When useful for clarification, portions of the pseudo-code are reproduced here too.
 */

    struct buffer_state {
        const uint8_t * p;
        size_t len;
        size_t total_len;
        int single_one_delivered; /* bool */
        int total_len_delivered; /* bool */
    };
    uint32_t right_rot(uint32_t value, unsigned int count);
    struct string_vector {
        const char *input;
        const char *output;
    };
    struct string_vector STRING_VECTORS[7];
    uint8_t data1[1];
    uint8_t data2[4];
    uint8_t data7[1000];
    uint8_t data8[1000];
    uint8_t data9[1005];
    uint8_t * data11;
    uint8_t * data12;
    uint8_t * data13;
    struct vector {
        const uint8_t *input;
        size_t input_len;
        const char *output;
    };
    struct vector vectors[13];
    void init_buf_state(buffer_state *state, const uint8_t *input, size_t len);
    int calc_chunk(uint8_t chunk[], buffer_state *state);
    void calc_sha_256(uint8_t hash[], const uint8_t *input, size_t len);
    void construct_binary_messages();
    void destruct_binary_messages();
    void hash_to_string(char string[], const uint8_t hash[]);
    int string_test(const char input[], const char output[]);
    int test(const uint8_t *input, size_t input_len, const char output[]);
signals:

};

#endif // SHA2_HPP
