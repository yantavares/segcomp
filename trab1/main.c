/**
 * @file main.c
 * @brief Implementação completa da cifra de Vigenère com ataque de análise de frequência
 *
 * Este programa implementa duas partes principais:
 * 1. Cifrador/Decifrador de Vigenère
 * 2. Ataque de recuperação de senha por análise de frequência
 *
 * Autor: Yan Tavares e Eduardo Marques
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>

#define MAX_TEXT_SIZE 10000
#define MAX_KEY_SIZE 100
#define ALPHABET_SIZE 26
#define MAX_KEY_LENGTH_TO_TRY 20
#define MIN_IC_DIFF 0.001 // Diferença mínima para considerar uma melhoria no IC

/**
 * @brief Frequência das letras em português
 * Fonte: https://pt.wikipedia.org/wiki/Frequ%C3%AAncia_de_letras
 */
const double pt_frequencies[ALPHABET_SIZE] = {
    0.1463, // A
    0.0104, // B
    0.0388, // C
    0.0499, // D
    0.1257, // E
    0.0102, // F
    0.0130, // G
    0.0128, // H
    0.0618, // I
    0.0040, // J
    0.0002, // K
    0.0278, // L
    0.0474, // M
    0.0505, // N
    0.1073, // O
    0.0252, // P
    0.0120, // Q
    0.0653, // R
    0.0781, // S
    0.0434, // T
    0.0463, // U
    0.0167, // V
    0.0001, // W
    0.0021, // X
    0.0001, // Y
    0.0047  // Z
};

/**
 * @brief Frequência das letras em inglês
 * Fonte: https://en.wikipedia.org/wiki/Letter_frequency
 */
const double en_frequencies[ALPHABET_SIZE] = {
    0.0817, 0.0149, 0.0278, 0.0425, 0.1270, 0.0223, 0.0202, 0.0609, 0.0697,
    0.0015, 0.0077, 0.0402, 0.0241, 0.0675, 0.0751, 0.0193, 0.0009, 0.0599,
    0.0633, 0.0906, 0.0276, 0.0098, 0.0236, 0.0015, 0.0197, 0.0007};

/**
 * @brief Cifra um texto usando a cifra de Vigenère
 *
 * A cifra de Vigenère é uma técnica de criptografia polialfabética que usa uma série de cifras
 * de César baseadas nas letras de uma palavra-chave. Para cada letra do texto, usa-se a letra
 * correspondente da chave para determinar o deslocamento.
 *
 * Fórmula: Ci = (Pi + Ki) mod 26
 * Onde:
 * - Ci é a letra cifrada
 * - Pi é a letra original (plaintext)
 * - Ki é a letra da chave
 *
 * @param plaintext Texto a ser cifrado
 * @param key Chave para cifração
 * @param ciphertext Buffer para armazenar o texto cifrado
 * @return Nada, o resultado é colocado no buffer ciphertext
 */
void vigenere_encrypt(const char *plaintext, const char *key, char *ciphertext)
{
    int key_len = strlen(key);
    int text_len = strlen(plaintext);
    int key_index = 0;
    int i, j;

    for (i = 0, j = 0; i < text_len; i++)
    {
        char c = plaintext[i];

        // Preserva caracteres não alfabéticos
        if (!isalpha(c))
        {
            ciphertext[j++] = c;
            continue;
        }

        // Cifra apenas caracteres alfabéticos
        int is_upper = isupper(c);
        c = tolower(c);

        // Calcula o valor cifrado (Ci = (Pi + Ki) mod 26)
        char key_char = tolower(key[key_index % key_len]);
        char encrypted = 'a' + ((c - 'a' + (key_char - 'a')) % ALPHABET_SIZE);

        // Preserva o caso original
        ciphertext[j++] = is_upper ? toupper(encrypted) : encrypted;

        key_index++;
    }

    ciphertext[j] = '\0';
}

/**
 * @brief Decifra um texto cifrado com a cifra de Vigenère
 *
 * A decifração é o processo inverso da cifração.
 *
 * Fórmula: Pi = (Ci - Ki + 26) mod 26
 * Onde:
 * - Pi é a letra original (plaintext)
 * - Ci é a letra cifrada
 * - Ki é a letra da chave
 *
 * @param ciphertext Texto cifrado a ser decifrado
 * @param key Chave para decifração
 * @param plaintext Buffer para armazenar o texto decifrado
 * @return Nada, o resultado é colocado no buffer plaintext
 */
void vigenere_decrypt(const char *ciphertext, const char *key, char *plaintext)
{
    int key_len = strlen(key);
    int text_len = strlen(ciphertext);
    int key_index = 0;
    int i, j;

    for (i = 0, j = 0; i < text_len; i++)
    {
        char c = ciphertext[i];

        // Preserva caracteres não alfabéticos
        if (!isalpha(c))
        {
            plaintext[j++] = c;
            continue;
        }

        // Decifra apenas caracteres alfabéticos
        int is_upper = isupper(c);
        c = tolower(c);

        // Calcula o valor decifrado (Pi = (Ci - Ki + 26) mod 26)
        char key_char = tolower(key[key_index % key_len]);
        char decrypted = 'a' + ((c - 'a' - (key_char - 'a') + ALPHABET_SIZE) % ALPHABET_SIZE);

        // Preserva o caso original
        plaintext[j++] = is_upper ? toupper(decrypted) : decrypted;

        key_index++;
    }

    plaintext[j] = '\0';
}

/**
 * @brief Conta a frequência de cada letra em um texto
 *
 * @param text Texto para analisar
 * @param freq Array para armazenar as frequências (deve ter tamanho ALPHABET_SIZE)
 * @return Número total de letras contadas
 */
int count_frequencies(const char *text, int *freq)
{
    int i;
    int total = 0;

    for (i = 0; i < ALPHABET_SIZE; i++)
    {
        freq[i] = 0;
    }

    // Conta a frequência de cada letra
    for (i = 0; text[i] != '\0'; i++)
    {
        if (isalpha(text[i]))
        {
            int index = tolower(text[i]) - 'a';
            freq[index]++;
            total++;
        }
    }

    return total;
}

/**
 * @brief Calcula o Índice de Coincidência (IC) de um texto
 *
 * O Índice de Coincidência é a probabilidade de duas letras selecionadas aleatoriamente
 * em um texto serem iguais. É uma medida útil para determinar se um texto foi cifrado
 * com uma cifra polialfabética (como Vigenère) ou monoalfabética.
 *
 * Fórmula: IC = Σ(fi * (fi - 1)) / (N * (N - 1))
 * Onde:
 * - fi é a frequência de cada letra
 * - N é o número total de letras
 *
* Para textos em inglês, o IC teórico (sum f_i^2) é aproximadamente 0.0667
* Para textos em português, o IC teórico (sum f_i^2) é aproximadamente 0.0761 (baseado nas frequências usadas)
 * Para textos totalmente aleatórios, o IC é aproximadamente 0,038 (1/26)
 *
 * @param text Texto para calcular o IC
 * @return Índice de Coincidência
 */
double index_of_coincidence(const char *text)
{
    int frequencies[ALPHABET_SIZE];
    int total = count_frequencies(text, frequencies);

    if (total <= 1)
    {
        return 0.0; // Evitar divisão por zero
    }

    double sum = 0.0;
    int i;

    for (i = 0; i < ALPHABET_SIZE; i++)
    {
        sum += frequencies[i] * (frequencies[i] - 1);
    }

    return sum / (total * (total - 1.0)); // Garantir divisão de ponto flutuante
}

/**
 * @brief Extrai uma subseção do texto a cada n posições
 *
 * Esta função é usada no ataque de Vigenère para extrair todas as letras que foram
 * cifradas com o mesmo caractere da chave (a cada key_length posições).
 *
 * @param text Texto original
 * @param key_length Tamanho da chave
 * @param offset Deslocamento a partir do início
 * @param result Buffer para armazenar o resultado
 */
void extract_sequence(const char *text, int key_length, int offset, char *result)
{
    int i, j = 0;
    int text_len = strlen(text);

    for (i = offset; i < text_len; i += key_length)
    {
        if (isalpha(text[i]))
        {
            result[j++] = tolower(text[i]);
        }
    }

    result[j] = '\0';
}

/**
 * @brief Calcula o Índice de Coincidência médio para um determinado tamanho de chave
 *
 * @param text Texto cifrado
 * @param key_length Tamanho da chave a testar
 * @return IC médio para o tamanho de chave dado
 */
double average_ic_for_key_length(const char *text, int key_length)
{
    double sum_ic = 0.0;
    char sequence[MAX_TEXT_SIZE];
    int i;

    if (key_length <= 0) return 0.0; // Evitar divisão por zero ou comportamento indefinido

    for (i = 0; i < key_length; i++)
    {
        extract_sequence(text, key_length, i, sequence);
        if (strlen(sequence) > 1) { // IC só faz sentido para sequências com mais de uma letra
            sum_ic += index_of_coincidence(sequence);
        }
    }
    // Se key_length for 0, isso causaria divisão por zero. Já tratado acima.
    return sum_ic / key_length;
}

/**
 * @brief Calcula o deslocamento mais provável para uma sequência (método do Qui-Quadrado)
 *
 * Este método usa o teste do Qui-Quadrado para encontrar o deslocamento que minimiza
 * a diferença entre as frequências observadas (deslocadas) e as frequências esperadas.
 *
 * Chi^2 = Σ ((Observada_i - Esperada_i)^2 / Esperada_i)
 *
 * @param sequence Sequência de texto
 * @param expected_freqs Frequências esperadas para o idioma
 * @return Deslocamento mais provável (0-25, correspondendo a 'a'-'z')
 */
int find_likely_shift_chi_squared(const char *sequence, const double *expected_freqs) {
    int observed_counts[ALPHABET_SIZE];
    int total_chars = count_frequencies(sequence, observed_counts);
    double min_chi_squared = -1.0;
    int best_shift = 0;
    int g; // g = shift (representa a letra da chave: 0 para 'a', 1 para 'b', etc.)

    if (total_chars == 0) {
        return 0; // Retorna 'a' como palpite se a sequência for vazia
    }

    for (g = 0; g < ALPHABET_SIZE; g++) { // Tenta cada possível letra da chave (0 a 25)
        double current_chi_squared = 0.0;
        int i; // Representa a letra do alfabeto (0 para 'a', 1 para 'b', etc.)
        for (i = 0; i < ALPHABET_SIZE; i++) {
            // Frequência observada da letra 'i' no texto decifrado com a chave 'g'
            // Se a letra no texto cifrado é 'c', e a chave é 'g', a letra decifrada é (c-g) mod 26.
            // Então, a contagem observada para a letra 'i' do texto plano é a contagem da letra (i+g)%26 no texto cifrado.
            double observed_count_for_plaintext_letter_i = (double)observed_counts[(i + g) % ALPHABET_SIZE];
            
            // Contagem esperada da letra 'i' no idioma
            double expected_count_for_plaintext_letter_i = expected_freqs[i] * total_chars;

            if (expected_count_for_plaintext_letter_i == 0) { 
                // Se a frequência esperada é 0, e a observada também é 0, não adiciona ao chi-quadrado.
                // Se a observada não é 0, adiciona um valor alto para penalizar.
                if (observed_count_for_plaintext_letter_i > 0) {
                    current_chi_squared += 1000; // Penalidade alta (arbitrária)
                }
            } else {
                current_chi_squared += pow(observed_count_for_plaintext_letter_i - expected_count_for_plaintext_letter_i, 2) / expected_count_for_plaintext_letter_i;
            }
        }

        if (min_chi_squared < 0 || current_chi_squared < min_chi_squared) {
            min_chi_squared = current_chi_squared;
            best_shift = g; // 'g' é a letra da chave que minimiza o Qui-Quadrado
        }
    }
    return best_shift; // Este é o caractere da chave (0='a', 1='b', ...)
}


/**
 * @brief Tenta recuperar a chave usada para cifrar o texto
 *
 * @param cleaned_ciphertext Texto cifrado (já limpo, contendo apenas letras)
 * @param key_length Tamanho da chave
 * @param is_portuguese Flag indicando se o texto está em português (1) ou inglês (0)
 * @param key Buffer para armazenar a chave recuperada
 */
void recover_key(const char *cleaned_ciphertext, int key_length, int is_portuguese, char *key)
{
    char sequence[MAX_TEXT_SIZE];
    int i;

    const double *expected_freqs = is_portuguese ? pt_frequencies : en_frequencies;

    for (i = 0; i < key_length; i++)
    {
        extract_sequence(cleaned_ciphertext, key_length, i, sequence);

        if (strlen(sequence) == 0) { // Se a subsequência for vazia
            key[i] = 'a'; // Assume 'a' ou poderia ser outra heurística
            continue;
        }
        // Encontra o deslocamento mais provável para esta posição da chave
        // O 'shift' retornado por find_likely_shift_chi_squared é a letra da chave (0='a', 1='b', etc.)
        int key_char_offset = find_likely_shift_chi_squared(sequence, expected_freqs);
        key[i] = 'a' + key_char_offset;
    }

    key[key_length] = '\0';
}

/**
 * @brief Determina o tamanho mais provável da chave
 *
 * Este método usa o Índice de Coincidência para determinar o tamanho mais provável da chave.
 * À medida que testamos diferentes comprimentos de chave, aquele que resultar em subsequências
 * com IC mais próximo ao esperado para o idioma (±0,065-0,075) provavelmente é o correto.
 *
 * @param cleaned_ciphertext Texto cifrado (já limpo, contendo apenas letras)
 * @param is_portuguese Flag indicando se o texto está em português (1) ou inglês (0)
 * @return Tamanho mais provável da chave
 */
int find_key_length(const char *cleaned_ciphertext, int is_portuguese)
{
    // IC teórico (sum f_i^2) para português: ~0.0761
    // IC teórico (sum f_i^2) para inglês: ~0.0667
    double target_ic = is_portuguese ? 0.0761384 : 0.066699; 
                                                    
    double best_avg_ic = 0.0; 
    int best_length = 1;
    int i;

    printf("\nProcurando o tamanho da chave (até %d)...\n", MAX_KEY_LENGTH_TO_TRY);
    printf("Comprimento | IC Médio Subsequências\n");
    printf("------------|-----------------------\n");

    // Testa comprimentos de chave de 1 a MAX_KEY_LENGTH_TO_TRY
    for (i = 1; i <= MAX_KEY_LENGTH_TO_TRY; i++)
    {
        if (strlen(cleaned_ciphertext) < i * 2 && i > 1 && i != 0) { 
            if (strlen(cleaned_ciphertext) / i < 2 ) { // Se cada subsequência tiver menos de 2 caracteres
                // printf("%-11d | (texto muito curto para subsequências significativas com este tamanho de chave)\n", i);
                continue;
            }
        }
        double avg_ic = average_ic_for_key_length(cleaned_ciphertext, i);
        printf("%-11d | %.5f\n", i, avg_ic);

        if (i == 1) { 
            best_avg_ic = avg_ic;
            best_length = 1;
        } else {
            // Prioriza o IC que está mais próximo do IC alvo do idioma.
            // MIN_IC_DIFF ajuda a preferir comprimentos menores se a melhoria na diferença for marginal.
            if (fabs(avg_ic - target_ic) < fabs(best_avg_ic - target_ic) - MIN_IC_DIFF) {
                best_avg_ic = avg_ic;
                best_length = i;
            } 
            // Se a diferença para o alvo for muito similar, mas o IC atual for maior (e ainda razoável)
            // Isso pode ajudar a desempatar casos onde um IC um pouco menor está numericamente mais perto do alvo
            // mas um IC maior (e ainda próximo) é mais indicativo de um texto não aleatório.
            else if (fabs(avg_ic - target_ic) < fabs(best_avg_ic - target_ic) + MIN_IC_DIFF/2 && avg_ic > best_avg_ic + MIN_IC_DIFF ) {
                best_avg_ic = avg_ic;
                best_length = i;
            }
        }
    }
    
    if (best_avg_ic < 0.045 && best_length > 1 && strlen(cleaned_ciphertext) > 50) { // 0.038 é aleatório
        printf("AVISO: O melhor IC médio (%.5f para tamanho %d) ainda é baixo. A determinação do tamanho da chave pode ser imprecisa.\n", best_avg_ic, best_length);
    }


    printf("\nTamanho de chave mais provável: %d (com IC médio: %.5f, IC alvo do idioma: %.5f)\n", best_length, best_avg_ic, target_ic);
    return best_length;
}

/**
 * @brief Lê um arquivo e carrega seu conteúdo para uma string
 *
 * @param filename Nome do arquivo
 * @param buffer Buffer para armazenar o conteúdo
 * @param max_size Tamanho máximo do buffer
 * @return 1 se bem-sucedido, 0 caso contrário
 */
int read_file(const char *filename, char *buffer, int max_size)
{
    FILE *file = fopen(filename, "r");
    if (!file)
    {
        printf("Erro ao abrir o arquivo %s\n", filename);
        return 0;
    }

    size_t bytes_read = fread(buffer, 1, max_size - 1, file);
    if (ferror(file)) {
        printf("Erro ao ler o arquivo %s\n", filename);
        fclose(file);
        return 0;
    }
    buffer[bytes_read] = '\0';

    fclose(file);
    return 1;
}

/**
 * @brief Escreve uma string para um arquivo
 *
 * @param filename Nome do arquivo
 * @param content Conteúdo a ser escrito
 * @return 1 se bem-sucedido, 0 caso contrário
 */
int write_file(const char *filename, const char *content)
{
    FILE *file = fopen(filename, "w");
    if (!file)
    {
        printf("Erro ao criar o arquivo %s\n", filename);
        return 0;
    }

    if (fputs(content, file) == EOF) {
        printf("Erro ao escrever no arquivo %s\n", filename);
        fclose(file);
        return 0;
    }
    fclose(file);
    return 1;
}

/**
 * @brief Remove caracteres não alfabéticos de uma string e converte para minúsculas
 *
 * @param text Texto original
 * @param cleaned Texto limpo (apenas alfabético e minúsculo)
 */
void clean_text_to_lower(const char *text, char *cleaned)
{
    int i, j = 0;

    for (i = 0; text[i] != '\0'; i++)
    {
        if (isalpha(text[i]))
        {
            cleaned[j++] = tolower(text[i]);
        }
    }

    cleaned[j] = '\0';
}

/**
 * @brief Menu para cifrar uma mensagem
 */
void encrypt_menu()
{
    char plaintext[MAX_TEXT_SIZE];
    char key[MAX_KEY_SIZE];
    char ciphertext[MAX_TEXT_SIZE];
    int choice;

    printf("\n===== CIFRAR MENSAGEM =====\n");

    printf("Escolha uma opção:\n");
    printf("1. Digitar o texto a ser cifrado\n");
    printf("2. Carregar o texto de um arquivo\n");
    printf("Opção: ");
    if (scanf("%d", &choice) != 1) {
        printf("Entrada inválida.\n");
        while(getchar()!='\n'); // Limpa buffer de entrada
        return;
    }
    while(getchar()!='\n'); // Consome o '\n'

    if (choice == 1)
    {
        printf("Digite o texto a ser cifrado (max %d caracteres):\n", MAX_TEXT_SIZE -1);
        if (fgets(plaintext, MAX_TEXT_SIZE, stdin) == NULL) {
            printf("Erro ao ler texto.\n");
            return;
        }
        plaintext[strcspn(plaintext, "\n")] = '\0'; // Remove o '\n' final
    }
    else if (choice == 2)
    {
        char filename[100];
        printf("Digite o nome do arquivo: ");
        if (fgets(filename, 100, stdin) == NULL) {
            printf("Erro ao ler nome do arquivo.\n");
            return;
        }
        filename[strcspn(filename, "\n")] = '\0';

        if (!read_file(filename, plaintext, MAX_TEXT_SIZE))
        {
            return;
        }
        printf("Arquivo '%s' carregado.\n", filename);
    }
    else
    {
        printf("Opção inválida!\n");
        return;
    }

    printf("Digite a chave (apenas letras, sem espaços, max %d caracteres): ", MAX_KEY_SIZE -1);
    if (fgets(key, MAX_KEY_SIZE, stdin) == NULL) {
        printf("Erro ao ler chave.\n");
        return;
    }
    key[strcspn(key, "\n")] = '\0';

    // Validação da chave (apenas letras)
    int key_is_valid = 1;
    if (strlen(key) == 0) {
        key_is_valid = 0;
    } else {
        for (int k_idx = 0; key[k_idx] != '\0'; k_idx++) {
            if (!isalpha(key[k_idx])) {
                key_is_valid = 0;
                break;
            }
        }
    }

    if (!key_is_valid) {
        printf("Chave inválida! Use apenas letras e não deixe a chave vazia.\n");
        return;
    }

    // Cifra o texto
    vigenere_encrypt(plaintext, key, ciphertext);

    printf("\nTexto cifrado:\n%s\n", ciphertext);

    printf("\nDeseja salvar o texto cifrado? (s/n): ");
    char save_choice_char;
    if (scanf(" %c", &save_choice_char) != 1) { 
        printf("Entrada inválida.\n");
        while(getchar()!='\n');
        return;
    }
    while(getchar()!='\n'); 

    if (save_choice_char == 's' || save_choice_char == 'S')
    {
        char filename[100];
        printf("Digite o nome do arquivo para salvar: ");
        if (fgets(filename, 100, stdin) == NULL) {
            printf("Erro ao ler nome do arquivo.\n");
            return;
        }
        filename[strcspn(filename, "\n")] = '\0';

        if (write_file(filename, ciphertext))
        {
            printf("Texto cifrado salvo com sucesso em '%s'!\n", filename);
        }
    }
}

/**
 * @brief Menu para decifrar uma mensagem
 */
void decrypt_menu()
{
    char ciphertext[MAX_TEXT_SIZE];
    char key[MAX_KEY_SIZE];
    char plaintext[MAX_TEXT_SIZE];
    int choice;

    printf("\n===== DECIFRAR MENSAGEM =====\n");

    printf("Escolha uma opção:\n");
    printf("1. Digitar o texto cifrado\n");
    printf("2. Carregar o texto cifrado de um arquivo\n");
    printf("Opção: ");
    if (scanf("%d", &choice) != 1) {
        printf("Entrada inválida.\n");
        while(getchar()!='\n');
        return;
    }
    while(getchar()!='\n'); 

    if (choice == 1)
    {
        printf("Digite o texto cifrado (max %d caracteres):\n", MAX_TEXT_SIZE-1);
        if (fgets(ciphertext, MAX_TEXT_SIZE, stdin) == NULL) {
            printf("Erro ao ler texto cifrado.\n");
            return;
        }
        ciphertext[strcspn(ciphertext, "\n")] = '\0';
    }
    else if (choice == 2)
    {
        char filename[100];
        printf("Digite o nome do arquivo: ");
        if (fgets(filename, 100, stdin) == NULL) {
            printf("Erro ao ler nome do arquivo.\n");
            return;
        }
        filename[strcspn(filename, "\n")] = '\0';

        if (!read_file(filename, ciphertext, MAX_TEXT_SIZE))
        {
            return;
        }
        printf("Arquivo '%s' carregado.\n", filename);
    }
    else
    {
        printf("Opção inválida!\n");
        return;
    }

    printf("Digite a chave (apenas letras, sem espaços, max %d caracteres): ", MAX_KEY_SIZE-1);
    if (fgets(key, MAX_KEY_SIZE, stdin) == NULL) {
        printf("Erro ao ler chave.\n");
        return;
    }
    key[strcspn(key, "\n")] = '\0';

    // Validação da chave (apenas letras)
    int key_is_valid = 1;
    if (strlen(key) == 0) {
        key_is_valid = 0;
    } else {
        for (int k_idx = 0; key[k_idx] != '\0'; k_idx++) {
            if (!isalpha(key[k_idx])) {
                key_is_valid = 0;
                break;
            }
        }
    }

    if (!key_is_valid) {
        printf("Chave inválida! Use apenas letras e não deixe a chave vazia.\n");
        return;
    }

    // Decifra o texto
    vigenere_decrypt(ciphertext, key, plaintext);

    printf("\nTexto decifrado:\n%s\n", plaintext);

    printf("\nDeseja salvar o texto decifrado? (s/n): ");
    char save_choice_char;
    if (scanf(" %c", &save_choice_char) != 1) {
        printf("Entrada inválida.\n");
        while(getchar()!='\n');
        return;
    }
    while(getchar()!='\n');

    if (save_choice_char == 's' || save_choice_char == 'S')
    {
        char filename[100];
        printf("Digite o nome do arquivo para salvar: ");
        if (fgets(filename, 100, stdin) == NULL) {
            printf("Erro ao ler nome do arquivo.\n");
            return;
        }
        filename[strcspn(filename, "\n")] = '\0';

        if (write_file(filename, plaintext))
        {
            printf("Texto decifrado salvo com sucesso em '%s'!\n", filename);
        }
    }
}

/**
 * @brief Menu para realizar o ataque de recuperação de senha
 */
void attack_menu()
{
    char ciphertext_input[MAX_TEXT_SIZE]; 
    char cleaned_text[MAX_TEXT_SIZE];    
    char recovered_key[MAX_KEY_SIZE];
    char plaintext_output[MAX_TEXT_SIZE]; 
    int choice, language_choice;

    printf("\n===== ATAQUE DE RECUPERAÇÃO DE SENHA =====\n");
    printf("Este módulo utiliza análise de frequência e Índice de Coincidência (IC)\n");
    printf("para tentar descobrir a chave usada na cifra de Vigenère.\n\n");

    printf("Escolha uma opção para fornecer o texto cifrado:\n");
    printf("1. Digitar o texto cifrado\n");
    printf("2. Carregar o texto cifrado de um arquivo\n");
    printf("Opção: ");
    if (scanf("%d", &choice) != 1) {
        printf("Entrada inválida.\n");
        while(getchar()!='\n');
        return;
    }
    while(getchar()!='\n'); 

    if (choice == 1)
    {
        printf("Digite o texto cifrado (max %d caracteres):\n", MAX_TEXT_SIZE-1);
        if (fgets(ciphertext_input, MAX_TEXT_SIZE, stdin) == NULL) {
            printf("Erro ao ler texto cifrado.\n");
            return;
        }
        ciphertext_input[strcspn(ciphertext_input, "\n")] = '\0';
    }
    else if (choice == 2)
    {
        char filename[100];
        printf("Digite o nome do arquivo contendo o texto cifrado: ");
        if (fgets(filename, 100, stdin) == NULL) {
            printf("Erro ao ler nome do arquivo.\n");
            return;
        }
        filename[strcspn(filename, "\n")] = '\0';

        if (!read_file(filename, ciphertext_input, MAX_TEXT_SIZE))
        {
            return; 
        }
        printf("Arquivo '%s' carregado.\n", filename);
    }
    else
    {
        printf("Opção inválida!\n");
        return;
    }

    printf("\nSelecione o idioma provável do texto original:\n");
    printf("1. Português\n");
    printf("2. Inglês\n");
    printf("Opção: ");
    if (scanf("%d", &language_choice) != 1) {
        printf("Entrada inválida.\n");
        while(getchar()!='\n');
        return;
    }
    while(getchar()!='\n');

    if (language_choice != 1 && language_choice != 2)
    {
        printf("Opção de idioma inválida!\n");
        return;
    }

    int is_portuguese = (language_choice == 1);

    clean_text_to_lower(ciphertext_input, cleaned_text);

    if (strlen(cleaned_text) == 0) {
        printf("O texto fornecido não contém letras para análise.\n");
        return;
    }
    if (strlen(cleaned_text) < MAX_KEY_LENGTH_TO_TRY * 2 && strlen(cleaned_text) > 0) { 
        printf("AVISO: O texto para análise é muito curto (%zu letras). Os resultados do ataque podem ser imprecisos, especialmente para chaves longas.\n", strlen(cleaned_text));
    }


    printf("\nIniciando análise do texto cifrado...\n");
    printf("Comprimento do texto cifrado original: %zu caracteres\n", strlen(ciphertext_input));
    printf("Comprimento do texto limpo para análise (apenas letras): %zu caracteres\n", strlen(cleaned_text));

    double global_ic = index_of_coincidence(cleaned_text);
    printf("\nÍndice de Coincidência (IC) global do texto limpo: %.5f\n", global_ic);
    printf("IC esperado para texto em %s (teórico): %.5f\n",
        is_portuguese ? "Português" : "Inglês",
        is_portuguese ? 0.0761384 : 0.066699); 
    printf("IC típico para texto aleatório (1/26): %.5f\n", 1.0/ALPHABET_SIZE);

    if (global_ic > (is_portuguese ? 0.072 : 0.063) && strlen(cleaned_text) > 50) { 
        printf("AVISO: O IC global é relativamente alto. O texto pode não estar cifrado com Vigenère (ou chave muito curta/simples).\n");
    } else if (global_ic > 0.0 && global_ic < 0.045 ) { 
        printf("Confirmado: O IC baixo sugere uma cifra polialfabética (como Vigenère).\n");
    } else if (global_ic == 0.0 && strlen(cleaned_text) > 0){
        printf("AVISO: O IC global é zero. Isso pode acontecer com textos muito curtos ou com padrões muito repetitivos.\n");
    }
    else {
        printf("O IC global está em uma zona intermediária ou o texto é curto. A análise prosseguirá.\n");
    }


    printf("\nDeseja especificar um tamanho de chave ou usar análise automática?\n");
    printf("1. Usar análise automática para determinar o tamanho da chave\n");
    printf("2. Especificar manualmente o tamanho da chave\n");
    printf("Opção: ");
    int key_length_option;
    if (scanf("%d", &key_length_option) != 1) {
        printf("Entrada inválida.\n");
        while(getchar()!='\n');
        return;
    }
    while(getchar()!='\n');

    int key_length_to_use;
    if (key_length_option == 1)
    {
        key_length_to_use = find_key_length(cleaned_text, is_portuguese);
    }
    else if (key_length_option == 2)
    {
        printf("Digite o tamanho da chave a ser testado (1-%d): ", MAX_KEY_LENGTH_TO_TRY); // MAX_KEY_LENGTH_TO_TRY é o limite superior para o ataque automático
        if (scanf("%d", &key_length_to_use) != 1) {
            printf("Entrada inválida.\n");
            while(getchar()!='\n');
            return;
        }
        while(getchar()!='\n');
        if (key_length_to_use <= 0 || key_length_to_use > MAX_KEY_SIZE -1 ) // Chave não pode ser maior que o buffer
        {
            printf("Tamanho de chave inválido (%d). Usando análise automática.\n", key_length_to_use);
            key_length_to_use = find_key_length(cleaned_text, is_portuguese);
        }
        else
        {
            printf("Usando tamanho de chave especificado: %d\n", key_length_to_use);
        }
    }
    else
    {
        printf("Opção inválida. Usando análise automática.\n");
        key_length_to_use = find_key_length(cleaned_text, is_portuguese);
    }

    if (key_length_to_use <=0) { 
        printf("Tamanho de chave inválido determinado (%d). Abortando ataque.\n", key_length_to_use);
        return;
    }
    if (key_length_to_use > strlen(cleaned_text)){
        printf("AVISO: O tamanho da chave determinado (%d) é maior que o texto limpo (%zu). Isso é improvável. Verifique o texto ou tente um tamanho de chave menor.\n", key_length_to_use, strlen(cleaned_text));
        // Poderia abortar ou pedir para o usuário confirmar/inserir manualmente.
        // Por ora, o ataque prosseguirá, mas provavelmente falhará.
    }


    // Recupera a chave
    recover_key(cleaned_text, key_length_to_use, is_portuguese, recovered_key);
    printf("\nChave recuperada (tentativa): \"%s\"\n", recovered_key);

    // Decifra o texto cifrado ORIGINAL (com pontuação, etc.) usando a chave recuperada
    vigenere_decrypt(ciphertext_input, recovered_key, plaintext_output);

    printf("\n===== RESULTADO FINAL DO ATAQUE =====\n");
    printf("Chave recuperada (tentativa): \"%s\" (comprimento: %d)\n", recovered_key, key_length_to_use);
    printf("\nTexto decifrado (tentativa):\n%s\n", plaintext_output);

    printf("\nDeseja salvar o texto decifrado e o relatório? (s/n): ");
    char save_choice_char;
    if (scanf(" %c", &save_choice_char) != 1) {
        printf("Entrada inválida.\n");
        while(getchar()!='\n');
        return;
    }
    while(getchar()!='\n');

    if (save_choice_char == 's' || save_choice_char == 'S')
    {
        char out_filename[100];
        char report_filename[115]; 

        printf("Digite o nome base para os arquivos de saída (ex: 'resultado_ataque'): ");
        if (fgets(out_filename, 100, stdin) == NULL) {
            printf("Erro ao ler nome base.\n");
            return;
        }
        out_filename[strcspn(out_filename, "\n")] = '\0';

        char decrypted_text_filename[110];
        snprintf(decrypted_text_filename, sizeof(decrypted_text_filename), "%s_decifrado.txt", out_filename);

        if (write_file(decrypted_text_filename, plaintext_output))
        {
            printf("Texto decifrado salvo com sucesso em '%s'!\n", decrypted_text_filename);
        }

        snprintf(report_filename, sizeof(report_filename), "%s_relatorio_ataque.txt", out_filename);
        FILE *report_file = fopen(report_filename, "w");
        if (report_file)
        {
            fprintf(report_file, "RELATÓRIO DE ANÁLISE CRIPTOGRÁFICA (CIFRA DE VIGENÈRE)\n");
            fprintf(report_file, "=========================================================\n\n");
            fprintf(report_file, "Idioma presumido do texto original: %s\n", is_portuguese ? "Português" : "Inglês");
            fprintf(report_file, "Texto cifrado original fornecido:\n--INICIO TEXTO--\n%s\n--FIM TEXTO--\n\n", ciphertext_input);
            fprintf(report_file, "Texto limpo usado para análise (apenas letras minúsculas):\n--INICIO TEXTO LIMPO--\n%s\n--FIM TEXTO LIMPO--\n\n", cleaned_text);
            fprintf(report_file, "Comprimento do texto cifrado original: %zu caracteres\n", strlen(ciphertext_input));
            fprintf(report_file, "Comprimento do texto limpo para análise: %zu letras\n", strlen(cleaned_text));
            fprintf(report_file, "Índice de Coincidência (IC) global do texto limpo: %.5f\n", global_ic);
            fprintf(report_file, "Tamanho de chave determinado/utilizado para o ataque: %d\n", key_length_to_use);
            fprintf(report_file, "Chave recuperada (tentativa): \"%s\"\n\n", recovered_key);
            fprintf(report_file, "TEXTO DECIFRADO (TENTATIVA):\n--INICIO TEXTO DECIFRADO--\n%s\n--FIM TEXTO DECIFRADO--\n", plaintext_output);
            fclose(report_file);
            printf("Relatório detalhado do ataque salvo em '%s'!\n", report_filename);
        } else {
            printf("Erro ao criar arquivo de relatório '%s'.\n", report_filename);
        }
    }
}

/**
 * @brief Função principal
 */
int main()
{
    int choice;

    do
    {
        printf("\n\n===== CIFRA DE VIGENÈRE - MENU PRINCIPAL =====\n");
        printf("1. Cifrar mensagem\n");
        printf("2. Decifrar mensagem\n");
        printf("3. Realizar ataque de recuperação de senha\n");
        printf("0. Sair\n");
        printf("Escolha uma opção: ");
        
        if (scanf("%d", &choice) != 1) {
            printf("Opção inválida! Por favor, digite um número.\n");
            while(getchar()!='\n');
            choice = -1; 
        } else {
            while(getchar()!='\n');
        }


        switch (choice)
        {
        case 1:
            encrypt_menu();
            break;
        case 2:
            decrypt_menu();
            break;
        case 3:
            attack_menu();
            break;
        case 0:
            printf("Saindo do programa...\n");
            break;
        default:
            if (choice != -1) { 
                printf("Opção inválida! Tente novamente.\n");
            }
        }
    } while (choice != 0);

    return 0;
}
