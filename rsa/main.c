/**
 * @file main.c
 * @brief Implementação de um gerador/verificador de assinaturas RSA.
 *
 * Este programa implementa as seguintes funcionalidades:
 * 1. Geração de pares de chaves RSA (pública e privada) de 2048 bits.
 * 2. Assinatura de arquivos usando RSA com padding OAEP e hash SHA3-256.
 * 3. Verificação de assinaturas em arquivos.
 *
 * O código utiliza a biblioteca GMP para aritmética de múltiplos precisão e implementa
 * SHA3-256 do zero. As primitivas criptográficas de geração de chaves
 * e cifração/decifração RSA-OAEP foram implementadas do zero.
 *
 * Autor: Yan Tavares e Eduardo Marques
 * Disciplina: CIC0201 - Segurança Computacional
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <gmp.h>
#include <stdint.h>

// --- Constantes ---
#define KEY_BITS 2048
#define MILLER_RABIN_ITERATIONS 40
#define SHA3_256_DIGEST_SIZE 32

// --- Implementação SHA3-256 do zero ---

/**
 * @brief Rotaciona bits à esquerda.
 */
static uint64_t rotl64(uint64_t x, int n)
{
    return (x << n) | (x >> (64 - n));
}

/**
 * @brief Implementação da função SHA3-256.
 * @param input Dados de entrada.
 * @param input_len Comprimento dos dados.
 * @param output Buffer para o hash (32 bytes).
 */
void sha3_256(const unsigned char *input, size_t input_len, unsigned char *output)
{
    // Constantes Keccak
    static const uint64_t keccak_round_constants[24] = {
        0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
        0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
        0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
        0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
        0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
        0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
        0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
        0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL};

    static const int rho_offsets[25] = {
        0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45,
        15, 21, 8, 18, 2, 61, 56, 14};

    uint64_t state[25] = {0};
    size_t rate = 136;    // 1088 bits = 136 bytes para SHA3-256
    size_t capacity = 64; // 512 bits = 64 bytes

    // Padding
    size_t padded_len = input_len;
    if ((input_len % rate) != (rate - 1))
    {
        padded_len = ((input_len / rate) + 1) * rate;
    }

    unsigned char *padded = calloc(padded_len, 1);
    memcpy(padded, input, input_len);

    // Aplicar padding 10*1
    padded[input_len] = 0x06; // SHA3 padding
    padded[padded_len - 1] |= 0x80;

    // Absorção
    for (size_t i = 0; i < padded_len; i += rate)
    {
        for (size_t j = 0; j < rate / 8; j++)
        {
            uint64_t word = 0;
            for (int k = 0; k < 8; k++)
            {
                if (i + j * 8 + k < padded_len)
                {
                    word |= ((uint64_t)padded[i + j * 8 + k]) << (k * 8);
                }
            }
            state[j] ^= word;
        }

        // Keccak-f[1600]
        for (int round = 0; round < 24; round++)
        {
            // θ (Theta)
            uint64_t C[5], D[5];
            for (int x = 0; x < 5; x++)
            {
                C[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
            }
            for (int x = 0; x < 5; x++)
            {
                D[x] = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1);
            }
            for (int x = 0; x < 5; x++)
            {
                for (int y = 0; y < 5; y++)
                {
                    state[y * 5 + x] ^= D[x];
                }
            }

            // ρ (Rho) and π (Pi)
            uint64_t current = state[1];
            for (int t = 0; t < 24; t++)
            {
                int x = ((t + 1) * (t + 2) / 2) % 25;
                uint64_t temp = state[x];
                state[x] = rotl64(current, rho_offsets[x]);
                current = temp;
            }

            // χ (Chi)
            for (int y = 0; y < 5; y++)
            {
                uint64_t temp[5];
                for (int x = 0; x < 5; x++)
                {
                    temp[x] = state[y * 5 + x];
                }
                for (int x = 0; x < 5; x++)
                {
                    state[y * 5 + x] = temp[x] ^ ((~temp[(x + 1) % 5]) & temp[(x + 2) % 5]);
                }
            }

            // ι (Iota)
            state[0] ^= keccak_round_constants[round];
        }
    }

    // Extração (squeeze)
    for (int i = 0; i < SHA3_256_DIGEST_SIZE; i++)
    {
        output[i] = (state[i / 8] >> ((i % 8) * 8)) & 0xFF;
    }

    free(padded);
}

// --- Funções de Base64 (Implementação auto-contida) ---

static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * @brief Codifica dados em Base64.
 * @param src Ponteiro para os dados de origem.
 * @param src_len Comprimento dos dados de origem.
 * @param out_len Ponteiro para armazenar o comprimento da saída.
 * @return Ponteiro para a string Base64 alocada (deve ser liberada).
 */
char *base64_encode(const unsigned char *src, size_t src_len, size_t *out_len)
{
    *out_len = 4 * ((src_len + 2) / 3);
    char *encoded_data = malloc(*out_len + 1);
    if (encoded_data == NULL)
        return NULL;

    for (size_t i = 0, j = 0; i < src_len;)
    {
        uint32_t octet_a = i < src_len ? (unsigned char)src[i++] : 0;
        uint32_t octet_b = i < src_len ? (unsigned char)src[i++] : 0;
        uint32_t octet_c = i < src_len ? (unsigned char)src[i++] : 0;
        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;
        encoded_data[j++] = b64_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = b64_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = b64_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = b64_table[(triple >> 0 * 6) & 0x3F];
    }

    int mod_table[] = {0, 2, 1};
    for (int i = 0; i < mod_table[src_len % 3]; i++)
    {
        encoded_data[*out_len - 1 - i] = '=';
    }
    encoded_data[*out_len] = '\0';
    return encoded_data;
}

/**
 * @brief Decodifica uma string Base64.
 * @param src Ponteiro para a string Base64.
 * @param src_len Comprimento da string Base64.
 * @param out_len Ponteiro para armazenar o comprimento dos dados decodificados.
 * @return Ponteiro para os dados decodificados (deve ser liberado).
 */
unsigned char *base64_decode(const char *src, size_t src_len, size_t *out_len)
{
    unsigned char dtable[256];
    memset(dtable, 0x80, 256);
    for (int i = 0; i < 64; i++)
        dtable[(unsigned char)b64_table[i]] = i;

    if (src_len % 4 != 0)
        return NULL;
    *out_len = src_len / 4 * 3;
    if (src[src_len - 1] == '=')
        (*out_len)--;
    if (src[src_len - 2] == '=')
        (*out_len)--;

    unsigned char *decoded_data = malloc(*out_len);
    if (decoded_data == NULL)
        return NULL;

    for (size_t i = 0, j = 0; i < src_len;)
    {
        uint32_t sextet_a = src[i] == '=' ? 0 & i++ : dtable[(unsigned char)src[i++]];
        uint32_t sextet_b = src[i] == '=' ? 0 & i++ : dtable[(unsigned char)src[i++]];
        uint32_t sextet_c = src[i] == '=' ? 0 & i++ : dtable[(unsigned char)src[i++]];
        uint32_t sextet_d = src[i] == '=' ? 0 & i++ : dtable[(unsigned char)src[i++]];
        uint32_t triple = (sextet_a << 3 * 6) + (sextet_b << 2 * 6) + (sextet_c << 1 * 6) + (sextet_d << 0 * 6);
        if (j < *out_len)
            decoded_data[j++] = (triple >> 2 * 8) & 0xFF;
        if (j < *out_len)
            decoded_data[j++] = (triple >> 1 * 8) & 0xFF;
        if (j < *out_len)
            decoded_data[j++] = (triple >> 0 * 8) & 0xFF;
    }
    return decoded_data;
}

// --- Funções Criptográficas ---

/**
 * @brief Teste de primalidade Miller-Rabin.
 * @param n Número a ser testado.
 * @param k Número de iterações.
 * @param rand_state Estado do gerador de números aleatórios.
 * @return 1 se provavelmente primo, 0 se composto.
 */
int miller_rabin_test(mpz_t n, int k, gmp_randstate_t rand_state)
{
    if (mpz_cmp_ui(n, 2) == 0 || mpz_cmp_ui(n, 3) == 0)
        return 1;
    if (mpz_cmp_ui(n, 1) <= 0 || mpz_even_p(n))
        return 0;

    mpz_t n_minus_1, d, a, x;
    mpz_inits(n_minus_1, d, a, x, NULL);

    mpz_sub_ui(n_minus_1, n, 1);
    mpz_set(d, n_minus_1);

    int r = 0;
    while (mpz_even_p(d))
    {
        mpz_divexact_ui(d, d, 2);
        r++;
    }

    for (int i = 0; i < k; i++)
    {
        mpz_urandomm(a, rand_state, n_minus_1);
        if (mpz_cmp_ui(a, 2) < 0)
            mpz_set_ui(a, 2);

        mpz_powm(x, a, d, n);

        if (mpz_cmp_ui(x, 1) == 0 || mpz_cmp(x, n_minus_1) == 0)
            continue;

        int composite = 1;
        for (int j = 0; j < r - 1; j++)
        {
            mpz_powm_ui(x, x, 2, n);
            if (mpz_cmp(x, n_minus_1) == 0)
            {
                composite = 0;
                break;
            }
        }

        if (composite)
        {
            mpz_clears(n_minus_1, d, a, x, NULL);
            return 0;
        }
    }

    mpz_clears(n_minus_1, d, a, x, NULL);
    return 1;
}

/**
 * @brief Gera um número primo com um número específico de bits usando Miller-Rabin.
 * @param prime Variável mpz_t para armazenar o primo.
 * @param bits O número de bits do primo.
 * @param rand_state Estado do gerador de números aleatórios do GMP.
 */
void generate_prime(mpz_t prime, int bits, gmp_randstate_t rand_state)
{
    do
    {
        mpz_urandomb(prime, rand_state, bits);
        mpz_setbit(prime, bits - 1); // Garante que tenha o número de bits correto
        mpz_setbit(prime, 0);        // Garante que seja ímpar
    } while (!miller_rabin_test(prime, MILLER_RABIN_ITERATIONS, rand_state) ||
             mpz_sizeinbase(prime, 2) != bits);
}

/**
 * @brief Gera um par de chaves RSA (pública e privada).
 * @param n Módulo RSA (saída).
 * @param e Expoente público (saída).
 * @param d Expoente privado (saída).
 * @param bits Número de bits para o módulo n.
 */
void generate_rsa_keys(mpz_t n, mpz_t e, mpz_t d, int bits)
{
    gmp_randstate_t rand_state;
    gmp_randinit_default(rand_state);
    gmp_randseed_ui(rand_state, time(NULL));

    mpz_t p, q, phi, gcd_result;
    mpz_inits(p, q, phi, gcd_result, NULL);

    printf("Gerando primo p de %d bits... ", bits / 2);
    fflush(stdout);
    generate_prime(p, bits / 2, rand_state);
    printf("OK\n");

    printf("Gerando primo q de %d bits... ", bits / 2);
    fflush(stdout);
    do
    {
        generate_prime(q, bits / 2, rand_state);
    } while (mpz_cmp(p, q) == 0); // Garante que p != q
    printf("OK\n");

    mpz_mul(n, p, q); // n = p * q

    mpz_sub_ui(p, p, 1); // p = p - 1
    mpz_sub_ui(q, q, 1); // q = q - 1
    mpz_mul(phi, p, q);  // phi = (p-1) * (q-1)

    mpz_set_ui(e, 65537); // e = 65537

    // Verifica se mdc(e, phi) = 1
    mpz_gcd(gcd_result, e, phi);
    if (mpz_cmp_ui(gcd_result, 1) != 0)
    {
        printf("Erro: e e phi não são coprimos. Tentando novamente.\n");
        mpz_clears(p, q, phi, gcd_result, NULL);
        gmp_randclear(rand_state);
        generate_rsa_keys(n, e, d, bits);
        return;
    }

    if (mpz_invert(d, e, phi) == 0)
    {
        printf("Erro: Inverso modular não existe. Tentando novamente.\n");
        mpz_clears(p, q, phi, gcd_result, NULL);
        gmp_randclear(rand_state);
        generate_rsa_keys(n, e, d, bits);
        return;
    }

    mpz_clears(p, q, phi, gcd_result, NULL);
    gmp_randclear(rand_state);
}

/**
 * @brief Função de Geração de Máscara (MGF1) para OAEP.
 * @param seed Seed para gerar a máscara.
 * @param seed_len Comprimento da seed.
 * @param mask Buffer para a máscara gerada (saída).
 * @param mask_len Comprimento da máscara a ser gerada.
 */
void mgf1(const unsigned char *seed, size_t seed_len, unsigned char *mask, size_t mask_len)
{
    unsigned char *counter = (unsigned char *)malloc(4);
    unsigned char *hash_input = (unsigned char *)malloc(seed_len + 4);
    unsigned char digest[SHA3_256_DIGEST_SIZE];
    size_t h_len = SHA3_256_DIGEST_SIZE;
    size_t offset = 0;

    for (uint32_t i = 0; offset < mask_len; i++)
    {
        counter[0] = (i >> 24) & 0xFF;
        counter[1] = (i >> 16) & 0xFF;
        counter[2] = (i >> 8) & 0xFF;
        counter[3] = i & 0xFF;

        memcpy(hash_input, seed, seed_len);
        memcpy(hash_input + seed_len, counter, 4);

        sha3_256(hash_input, seed_len + 4, digest);

        size_t copy_len = (offset + h_len <= mask_len) ? h_len : mask_len - offset;
        memcpy(mask + offset, digest, copy_len);
        offset += h_len;
    }
    free(counter);
    free(hash_input);
}

/**
 * @brief Implementa o padding RSA-OAEP.
 * @param message Mensagem a ser formatada.
 * @param message_len Comprimento da mensagem.
 * @param k Tamanho do módulo RSA em bytes.
 * @param padded_message Buffer para a mensagem formatada (saída).
 * @return 1 em sucesso, 0 em falha.
 */
int rsa_oaep_pad(const unsigned char *message, size_t message_len, int k, unsigned char **padded_message)
{
    unsigned int h_len = SHA3_256_DIGEST_SIZE;

    if (message_len > k - 2 * h_len - 2)
    {
        printf("Erro: Mensagem muito longa para OAEP.\n");
        return 0;
    }

    *padded_message = (unsigned char *)malloc(k);
    memset(*padded_message, 0, k);

    unsigned char l_hash[SHA3_256_DIGEST_SIZE];
    sha3_256((const unsigned char *)"", 0, l_hash); // Label vazia

    size_t ps_len = k - message_len - 2 * h_len - 2;
    size_t db_len = h_len + ps_len + 1 + message_len;
    unsigned char *db = (unsigned char *)malloc(db_len);

    memcpy(db, l_hash, h_len);
    memset(db + h_len, 0, ps_len);
    db[h_len + ps_len] = 0x01;
    memcpy(db + h_len + ps_len + 1, message, message_len);

    unsigned char seed[h_len];
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f)
    {
        // Fallback para sistemas sem /dev/urandom
        srand(time(NULL));
        for (size_t i = 0; i < h_len; i++)
        {
            seed[i] = rand() & 0xFF;
        }
    }
    else
    {
        fread(seed, 1, h_len, f);
        fclose(f);
    }

    unsigned char *db_mask = (unsigned char *)malloc(db_len);
    mgf1(seed, h_len, db_mask, db_len);

    unsigned char *masked_db = (unsigned char *)malloc(db_len);
    for (size_t i = 0; i < db_len; i++)
    {
        masked_db[i] = db[i] ^ db_mask[i];
    }

    unsigned char *seed_mask = (unsigned char *)malloc(h_len);
    mgf1(masked_db, db_len, seed_mask, h_len);

    unsigned char *masked_seed = (unsigned char *)malloc(h_len);
    for (size_t i = 0; i < h_len; i++)
    {
        masked_seed[i] = seed[i] ^ seed_mask[i];
    }

    // Constrói a mensagem final formatada EM
    (*padded_message)[0] = 0x00;
    memcpy((*padded_message) + 1, masked_seed, h_len);
    memcpy((*padded_message) + 1 + h_len, masked_db, db_len);

    free(db);
    free(db_mask);
    free(masked_db);
    free(seed_mask);
    free(masked_seed);

    return 1;
}

/**
 * @brief Remove o padding RSA-OAEP.
 * @param padded_message Mensagem formatada.
 * @param k Tamanho do módulo RSA em bytes.
 * @param message Buffer para a mensagem original (saída).
 * @param message_len Ponteiro para o comprimento da mensagem (saída).
 * @return 1 em sucesso, 0 em falha.
 */
int rsa_oaep_unpad(const unsigned char *padded_message, int k, unsigned char **message, size_t *message_len)
{
    unsigned int h_len = SHA3_256_DIGEST_SIZE;

    if (k < 2 * h_len + 2)
    {
        return 0;
    }

    const unsigned char *masked_seed = padded_message + 1;
    const unsigned char *masked_db = padded_message + 1 + h_len;
    size_t db_len = k - 1 - h_len;

    unsigned char *seed_mask = (unsigned char *)malloc(h_len);
    mgf1(masked_db, db_len, seed_mask, h_len);

    unsigned char *seed = (unsigned char *)malloc(h_len);
    for (size_t i = 0; i < h_len; i++)
    {
        seed[i] = masked_seed[i] ^ seed_mask[i];
    }

    unsigned char *db_mask = (unsigned char *)malloc(db_len);
    mgf1(seed, h_len, db_mask, db_len);

    unsigned char *db = (unsigned char *)malloc(db_len);
    for (size_t i = 0; i < db_len; i++)
    {
        db[i] = masked_db[i] ^ db_mask[i];
    }

    unsigned char l_hash_prime[SHA3_256_DIGEST_SIZE];
    sha3_256((const unsigned char *)"", 0, l_hash_prime);

    if (memcmp(db, l_hash_prime, h_len) != 0)
    {
        printf("Erro de unpadding: lHash não corresponde.\n");
        free(seed_mask);
        free(seed);
        free(db_mask);
        free(db);
        return 0;
    }

    // Encontra o separador 0x01
    size_t separator_idx = h_len;
    while (separator_idx < db_len && db[separator_idx] == 0x00)
    {
        separator_idx++;
    }

    if (separator_idx == db_len || db[separator_idx] != 0x01)
    {
        printf("Erro de unpadding: Separador 0x01 não encontrado.\n");
        free(seed_mask);
        free(seed);
        free(db_mask);
        free(db);
        return 0;
    }

    *message_len = db_len - separator_idx - 1;
    *message = (unsigned char *)malloc(*message_len);
    memcpy(*message, db + separator_idx + 1, *message_len);

    free(seed_mask);
    free(seed);
    free(db_mask);
    free(db);

    return 1;
}

// --- Funções de Arquivo e UI ---

/**
 * @brief Lê o conteúdo completo de um arquivo.
 * @param filename Nome do arquivo.
 * @param buffer Ponteiro para o buffer que armazenará o conteúdo.
 * @param len Ponteiro para o tamanho do conteúdo lido.
 * @return 1 em sucesso, 0 em falha.
 */
int read_file_content(const char *filename, unsigned char **buffer, size_t *len)
{
    FILE *f = fopen(filename, "rb");
    if (!f)
        return 0;
    fseek(f, 0, SEEK_END);
    *len = ftell(f);
    fseek(f, 0, SEEK_SET);
    *buffer = malloc(*len);
    if (!*buffer)
    {
        fclose(f);
        return 0;
    }
    if (fread(*buffer, 1, *len, f) != *len)
    {
        free(*buffer);
        fclose(f);
        return 0;
    }
    fclose(f);
    return 1;
}

/**
 * @brief Salva chaves RSA em arquivos.
 * @param n Módulo n.
 * @param e Expoente público e.
 * @param d Expoente privado d.
 */
void save_keys(mpz_t n, mpz_t e, mpz_t d)
{
    char *n_str = mpz_get_str(NULL, 16, n);
    char *e_str = mpz_get_str(NULL, 16, e);
    char *d_str = mpz_get_str(NULL, 16, d);

    FILE *pub_file = fopen("public_key.txt", "w");
    fprintf(pub_file, "%s\n%s", n_str, e_str);
    fclose(pub_file);

    FILE *priv_file = fopen("private_key.txt", "w");
    fprintf(priv_file, "%s\n%s", n_str, d_str);
    fclose(priv_file);

    printf("Chaves salvas em 'public_key.txt' e 'private_key.txt'.\n");

    free(n_str);
    free(e_str);
    free(d_str);
}

/**
 * @brief Carrega uma chave RSA (pública ou privada) de um arquivo.
 * @param filename Nome do arquivo da chave.
 * @param n Módulo n (saída).
 * @param exp Expoente e ou d (saída).
 * @return 1 em sucesso, 0 em falha.
 */
int load_key(const char *filename, mpz_t n, mpz_t exp)
{
    FILE *f = fopen(filename, "r");
    if (!f)
        return 0;

    if (mpz_inp_str(n, f, 16) == 0)
    {
        fclose(f);
        return 0;
    }
    if (mpz_inp_str(exp, f, 16) == 0)
    {
        fclose(f);
        return 0;
    }

    fclose(f);
    return 1;
}

/**
 * @brief Menu para gerar um par de chaves RSA.
 */
void generate_keys_menu()
{
    mpz_t n, e, d;
    mpz_inits(n, e, d, NULL);

    printf("\nGerando par de chaves RSA de %d bits...\n", KEY_BITS);
    printf("Testando primalidade com Miller-Rabin (%d iterações)...\n", MILLER_RABIN_ITERATIONS);
    generate_rsa_keys(n, e, d, KEY_BITS);
    save_keys(n, e, d);

    mpz_clears(n, e, d, NULL);
}

/**
 * @brief Função wrapper para calcular SHA3-256.
 * @param input Dados de entrada.
 * @param input_len Comprimento dos dados.
 * @param output Ponteiro para o buffer do hash (será alocado).
 * @param output_len Ponteiro para o comprimento do hash.
 */
void sha3_hash(const unsigned char *input, size_t input_len, unsigned char **output, unsigned int *output_len)
{
    *output = malloc(SHA3_256_DIGEST_SIZE);
    sha3_256(input, input_len, *output);
    *output_len = SHA3_256_DIGEST_SIZE;
}

/**
 * @brief Menu para assinar um arquivo.
 */
void sign_file_menu()
{
    char file_to_sign[256], key_file[256];
    unsigned char *file_content, *file_hash;
    unsigned int hash_len;
    size_t file_len;

    printf("Digite o nome do arquivo a ser assinado: ");
    scanf("%255s", file_to_sign);
    printf("Digite o nome do arquivo da chave privada (ex: private_key.txt): ");
    scanf("%255s", key_file);

    if (!read_file_content(file_to_sign, &file_content, &file_len))
    {
        printf("Erro: Não foi possível ler o arquivo '%s'.\n", file_to_sign);
        return;
    }

    mpz_t n, d;
    mpz_inits(n, d, NULL);
    if (!load_key(key_file, n, d))
    {
        printf("Erro: Não foi possível carregar a chave privada de '%s'.\n", key_file);
        free(file_content);
        mpz_clears(n, d, NULL);
        return;
    }

    // 1. Calcular o hash do arquivo
    sha3_hash(file_content, file_len, &file_hash, &hash_len);

    // 2. Aplicar padding OAEP ao hash
    int k = mpz_sizeinbase(n, 256);
    unsigned char *padded_hash;
    if (!rsa_oaep_pad(file_hash, hash_len, k, &padded_hash))
    {
        printf("Erro ao aplicar padding OAEP.\n");
        free(file_content);
        free(file_hash);
        mpz_clears(n, d, NULL);
        return;
    }

    // 3. "Cifrar" o hash com padding usando a chave privada (operação de assinatura)
    mpz_t padded_hash_mpz, signature_mpz;
    mpz_inits(padded_hash_mpz, signature_mpz, NULL);
    mpz_import(padded_hash_mpz, k, 1, sizeof(unsigned char), 0, 0, padded_hash);
    mpz_powm(signature_mpz, padded_hash_mpz, d, n);

    size_t signature_len;
    unsigned char *signature = (unsigned char *)mpz_export(NULL, &signature_len, 1, sizeof(unsigned char), 0, 0, signature_mpz);

    // 4. Formatar a saída
    size_t content_b64_len, sig_b64_len;
    char *content_b64 = base64_encode(file_content, file_len, &content_b64_len);
    char *sig_b64 = base64_encode(signature, signature_len, &sig_b64_len);

    char signed_filename[300];
    snprintf(signed_filename, sizeof(signed_filename), "%s.signed", file_to_sign);

    FILE *out_file = fopen(signed_filename, "w");
    if (!out_file)
    {
        printf("Erro ao criar arquivo de saída '%s'.\n", signed_filename);
    }
    else
    {
        fprintf(out_file, "-----BEGIN SIGNED MESSAGE-----\n");
        fprintf(out_file, "%s\n", content_b64);
        fprintf(out_file, "-----BEGIN SIGNATURE-----\n");
        fprintf(out_file, "%s\n", sig_b64);
        fprintf(out_file, "-----END SIGNATURE-----\n");
        fclose(out_file);
        printf("Arquivo assinado com sucesso e salvo como '%s'.\n", signed_filename);
    }

    // Limpeza
    free(file_content);
    free(file_hash);
    free(padded_hash);
    free(signature);
    free(content_b64);
    free(sig_b64);
    mpz_clears(n, d, padded_hash_mpz, signature_mpz, NULL);
}

/**
 * @brief Menu para verificar a assinatura de um arquivo.
 */
void verify_file_menu()
{
    char signed_file_name[256], key_file[256];

    printf("Digite o nome do arquivo assinado (ex: arquivo.txt.signed): ");
    scanf("%255s", signed_file_name);
    printf("Digite o nome do arquivo da chave pública (ex: public_key.txt): ");
    scanf("%255s", key_file);

    mpz_t n, e;
    mpz_inits(n, e, NULL);
    if (!load_key(key_file, n, e))
    {
        printf("Erro: Não foi possível carregar a chave pública de '%s'.\n", key_file);
        mpz_clears(n, e, NULL);
        return;
    }

    // 1. Ler e parsear o arquivo assinado
    FILE *f = fopen(signed_file_name, "r");
    if (!f)
    {
        printf("Erro ao abrir o arquivo assinado '%s'.\n", signed_file_name);
        mpz_clears(n, e, NULL);
        return;
    }

    char line[1024];
    char *content_b64 = NULL;
    char *sig_b64 = NULL;
    size_t content_alloc = 0, sig_alloc = 0;
    size_t content_len = 0, sig_len = 0;
    int reading_content = 0, reading_sig = 0;

    while (fgets(line, sizeof(line), f))
    {
        if (strncmp(line, "-----BEGIN SIGNED MESSAGE-----", 29) == 0)
        {
            reading_content = 1;
            reading_sig = 0;
            continue;
        }
        else if (strncmp(line, "-----BEGIN SIGNATURE-----", 24) == 0)
        {
            reading_content = 0;
            reading_sig = 1;
            continue;
        }
        else if (strncmp(line, "-----END SIGNATURE-----", 22) == 0)
        {
            reading_sig = 0;
            break;
        }

        if (reading_content)
        {
            size_t line_len = strlen(line);
            if (line[line_len - 1] == '\n')
                line_len--;
            if (content_len + line_len + 1 > content_alloc)
            {
                content_alloc = (content_alloc == 0) ? line_len + 1 : content_alloc * 2;
                content_b64 = realloc(content_b64, content_alloc);
            }
            memcpy(content_b64 + content_len, line, line_len);
            content_len += line_len;
        }
        else if (reading_sig)
        {
            size_t line_len = strlen(line);
            if (line[line_len - 1] == '\n')
                line_len--;
            if (sig_len + line_len + 1 > sig_alloc)
            {
                sig_alloc = (sig_alloc == 0) ? line_len + 1 : sig_alloc * 2;
                sig_b64 = realloc(sig_b64, sig_alloc);
            }
            memcpy(sig_b64 + sig_len, line, line_len);
            sig_len += line_len;
        }
    }
    fclose(f);
    if (content_b64)
        content_b64[content_len] = '\0';
    if (sig_b64)
        sig_b64[sig_len] = '\0';

    if (!content_b64 || !sig_b64)
    {
        printf("Erro: Formato de arquivo assinado inválido.\n");
        free(content_b64);
        free(sig_b64);
        mpz_clears(n, e, NULL);
        return;
    }

    // 2. Decodificar Base64
    size_t original_content_len, signature_len;
    unsigned char *original_content = base64_decode(content_b64, content_len, &original_content_len);
    unsigned char *signature = base64_decode(sig_b64, sig_len, &signature_len);

    // 3. "Decifrar" a assinatura com a chave pública
    mpz_t signature_mpz, decrypted_padded_hash_mpz;
    mpz_inits(signature_mpz, decrypted_padded_hash_mpz, NULL);
    mpz_import(signature_mpz, signature_len, 1, sizeof(unsigned char), 0, 0, signature);
    mpz_powm(decrypted_padded_hash_mpz, signature_mpz, e, n);

    int k = mpz_sizeinbase(n, 256);
    size_t decrypted_padded_hash_len;
    unsigned char *decrypted_padded_hash = (unsigned char *)mpz_export(NULL, &decrypted_padded_hash_len, 1, sizeof(unsigned char), 0, 0, decrypted_padded_hash_mpz);

    // Garantir que a saída tenha o tamanho K (preencher com zeros à esquerda se necessário)
    unsigned char *final_padded_hash = calloc(k, 1);
    memcpy(final_padded_hash + (k - decrypted_padded_hash_len), decrypted_padded_hash, decrypted_padded_hash_len);

    // 4. Remover o padding OAEP para obter o hash original
    unsigned char *original_hash;
    size_t original_hash_len;
    if (!rsa_oaep_unpad(final_padded_hash, k, &original_hash, &original_hash_len))
    {
        printf("\n=========================\n");
        printf("VERIFICAÇÃO FALHOU! (Erro no unpadding)\n");
        printf("=========================\n");
    }
    else
    {
        // 5. Calcular o hash do conteúdo original e comparar
        unsigned char *calculated_hash;
        unsigned int calculated_hash_len;
        sha3_hash(original_content, original_content_len, &calculated_hash, &calculated_hash_len);

        if (original_hash_len == calculated_hash_len && memcmp(original_hash, calculated_hash, original_hash_len) == 0)
        {
            printf("\n=========================\n");
            printf("ASSINATURA VÁLIDA!\n");
            printf("=========================\n");
        }
        else
        {
            printf("\n=========================\n");
            printf("VERIFICAÇÃO FALHOU! (Hashes não correspondem)\n");
            printf("=========================\n");
        }
        free(original_hash);
        free(calculated_hash);
    }

    // Limpeza
    free(content_b64);
    free(sig_b64);
    free(original_content);
    free(signature);
    free(decrypted_padded_hash);
    free(final_padded_hash);
    mpz_clears(n, e, signature_mpz, decrypted_padded_hash_mpz, NULL);
}

/**
 * @brief Menu para extrair a mensagem original de um arquivo assinado.
 */
void extract_message_menu()
{
    char signed_file_name[256], output_file[256];

    printf("Digite o nome do arquivo assinado (ex: arquivo.txt.signed): ");
    scanf("%255s", signed_file_name);

    // 1. Ler e parsear o arquivo assinado
    FILE *f = fopen(signed_file_name, "r");
    if (!f)
    {
        printf("Erro ao abrir o arquivo assinado '%s'.\n", signed_file_name);
        return;
    }

    char line[1024];
    char *content_b64 = NULL;
    size_t content_alloc = 0;
    size_t content_len = 0;
    int reading_content = 0;

    while (fgets(line, sizeof(line), f))
    {
        if (strncmp(line, "-----BEGIN SIGNED MESSAGE-----", 29) == 0)
        {
            reading_content = 1;
            continue;
        }
        else if (strncmp(line, "-----BEGIN SIGNATURE-----", 24) == 0)
        {
            reading_content = 0;
            break;
        }

        if (reading_content)
        {
            size_t line_len = strlen(line);
            if (line[line_len - 1] == '\n')
                line_len--;
            if (content_len + line_len + 1 > content_alloc)
            {
                content_alloc = (content_alloc == 0) ? line_len + 1 : content_alloc * 2;
                content_b64 = realloc(content_b64, content_alloc);
            }
            memcpy(content_b64 + content_len, line, line_len);
            content_len += line_len;
        }
    }
    fclose(f);

    if (content_b64)
        content_b64[content_len] = '\0';

    if (!content_b64)
    {
        printf("Erro: Não foi possível encontrar a mensagem no arquivo assinado.\n");
        return;
    }

    // 2. Decodificar Base64
    size_t original_content_len;
    unsigned char *original_content = base64_decode(content_b64, content_len, &original_content_len);

    if (!original_content)
    {
        printf("Erro: Não foi possível decodificar a mensagem Base64.\n");
        free(content_b64);
        return;
    }

    printf("\nConteúdo da mensagem: ");
    for (size_t i = 0; i < original_content_len; i++)
    {
        printf("%c", original_content[i]);
    }
    printf("\n\n");

    printf("Deseja salvar a mensagem original em um arquivo? (s/n): ");
    char save_choice;
    scanf(" %c", &save_choice);
    if (save_choice == 's' || save_choice == 'S')
    {
        printf("Digite o nome do arquivo de saída (ex: mensagem.txt): ");
        scanf("%255s", output_file);

        FILE *out_file = fopen(output_file, "wb");
        if (!out_file)
        {
            printf("Erro ao criar o arquivo de saída '%s'.\n", output_file);
        }
        else
        {
            fwrite(original_content, 1, original_content_len, out_file);
            fclose(out_file);
            printf("Mensagem original salva em '%s'.\n", output_file);
        }
    }
    else
    {
        printf("Mensagem original não salva.\n");
    }
    // Limpeza
    free(content_b64);
    free(original_content);
}

/**
 * @brief Função principal com o menu de interação (versão atualizada).
 */
int main()
{
    int choice;

    do
    {
        printf("\n\n===== ASSINATURA DIGITAL RSA - MENU PRINCIPAL =====\n");
        printf("1. Gerar chaves RSA\n");
        printf("2. Assinar arquivo\n");
        printf("3. Verificar assinatura\n");
        printf("4. Extrair mensagem original (arquivo .txt)\n");
        printf("0. Sair\n");
        printf("Escolha uma opção: ");

        if (scanf("%d", &choice) != 1)
        {
            printf("Opção inválida! Por favor, digite um número.\n");
            while (getchar() != '\n')
                ; // Limpa buffer de entrada
            choice = -1;
        }
        else
        {
            while (getchar() != '\n')
                ; // Consome o '\n' restante
        }

        switch (choice)
        {
        case 1:
            generate_keys_menu();
            break;
        case 2:
            sign_file_menu();
            break;
        case 3:
            verify_file_menu();
            break;
        case 4:
            extract_message_menu();
            break;
        case 0:
            printf("Saindo do programa...\n");
            break;
        default:
            if (choice != -1)
            {
                printf("Opção inválida! Tente novamente.\n");
            }
        }
    } while (choice != 0);

    return 0;
}