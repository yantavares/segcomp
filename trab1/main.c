/**
 * @file vigenere.c
 * @brief Implementação completa da cifra de Vigenère com ataque de análise de frequência
 *
 * Este programa implementa duas partes principais:
 * 1. Cifrador/Decifrador de Vigenère
 * 2. Ataque de recuperação de senha por análise de frequência
 *
 * Autor: Yan Tavares
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
    0.1463, 0.0104, 0.0388, 0.0499, 0.1257, 0.0102, 0.0130, 0.0128, 0.0618,
    0.0040, 0.0002, 0.0278, 0.0474, 0.0505, 0.1073, 0.0252, 0.0120, 0.0653,
    0.0781, 0.0434, 0.0463, 0.0167, 0.0001, 0.0021, 0.0001, 0.0047};

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

        // Avança para o próximo caractere da chave
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

        // Avança para o próximo caractere da chave
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

    // Inicializa o array de frequências com zeros
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
 * Para textos em inglês, o IC é aproximadamente 0,067
 * Para textos em português, o IC é aproximadamente 0,072
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

    return sum / (total * (total - 1));
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

    for (i = 0; i < key_length; i++)
    {
        extract_sequence(text, key_length, i, sequence);
        sum_ic += index_of_coincidence(sequence);
    }

    return sum_ic / key_length;
}

/**
 * @brief Calcula o deslocamento mais provável para uma sequência
 *
 * Este método usa a correlação entre as frequências observadas e as frequências
 * esperadas para determinar o deslocamento mais provável (letra da chave).
 *
 * @param sequence Sequência de texto
 * @param expected_freqs Frequências esperadas para o idioma
 * @return Deslocamento mais provável (0-25, correspondendo a 'a'-'z')
 */
int find_likely_shift(const char *sequence, const double *expected_freqs)
{
    int frequencies[ALPHABET_SIZE];
    int total = count_frequencies(sequence, frequencies);
    double correlations[ALPHABET_SIZE];
    int i, j, best_shift = 0;
    double max_correlation = -1.0;

    // Testa cada possível deslocamento
    for (i = 0; i < ALPHABET_SIZE; i++)
    {
        double correlation = 0.0;

        // Calcula a correlação entre as frequências observadas (deslocadas) e as esperadas
        for (j = 0; j < ALPHABET_SIZE; j++)
        {
            int shift_index = (j + i) % ALPHABET_SIZE;
            correlation += (double)frequencies[j] / total * expected_freqs[shift_index];
        }

        correlations[i] = correlation;

        // Atualiza o melhor deslocamento encontrado
        if (correlation > max_correlation)
        {
            max_correlation = correlation;
            best_shift = i;
        }
    }

    return best_shift;
}

/**
 * @brief Tenta recuperar a chave usada para cifrar o texto
 *
 * @param ciphertext Texto cifrado
 * @param key_length Tamanho da chave
 * @param is_portuguese Flag indicando se o texto está em português (1) ou inglês (0)
 * @param key Buffer para armazenar a chave recuperada
 */
void recover_key(const char *ciphertext, int key_length, int is_portuguese, char *key)
{
    char sequence[MAX_TEXT_SIZE];
    int i;

    for (i = 0; i < key_length; i++)
    {
        extract_sequence(ciphertext, key_length, i, sequence);

        // Escolhe o conjunto de frequências esperadas com base no idioma
        const double *expected_freqs = is_portuguese ? pt_frequencies : en_frequencies;

        // Encontra o deslocamento mais provável para esta posição da chave
        int shift = find_likely_shift(sequence, expected_freqs);

        // Converte o deslocamento para a letra correspondente
        key[i] = 'a' + ((ALPHABET_SIZE - shift) % ALPHABET_SIZE);
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
 * @param ciphertext Texto cifrado
 * @param is_portuguese Flag indicando se o texto está em português (1) ou inglês (0)
 * @return Tamanho mais provável da chave
 */
int find_key_length(const char *ciphertext, int is_portuguese)
{
    double expected_ic = is_portuguese ? 0.072 : 0.067; // IC esperado para o idioma
    double best_ic_diff = 1.0;                          // Inicializa com um valor alto
    int best_length = 1;
    int i;

    printf("\nProcurando o tamanho da chave...\n");
    printf("Comprimento | Índice de Coincidência Médio\n");
    printf("------------|---------------------------\n");

    // Testa comprimentos de chave de 1 a MAX_KEY_LENGTH_TO_TRY
    for (i = 1; i <= MAX_KEY_LENGTH_TO_TRY; i++)
    {
        double avg_ic = average_ic_for_key_length(ciphertext, i);
        double ic_diff = fabs(avg_ic - expected_ic);

        printf("%-11d | %-7.5f\n", i, avg_ic);

        // Se este comprimento produz um IC mais próximo do esperado
        if (ic_diff < best_ic_diff - MIN_IC_DIFF)
        {
            best_ic_diff = ic_diff;
            best_length = i;
        }
    }

    printf("\nTamanho de chave mais provável: %d\n", best_length);
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

    int size = fread(buffer, 1, max_size - 1, file);
    buffer[size] = '\0';

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

    fputs(content, file);
    fclose(file);
    return 1;
}

/**
 * @brief Remove caracteres não alfabéticos de uma string
 *
 * @param text Texto original
 * @param cleaned Texto limpo (apenas alfabético)
 */
void clean_text(const char *text, char *cleaned)
{
    int i, j = 0;

    for (i = 0; text[i] != '\0'; i++)
    {
        if (isalpha(text[i]))
        {
            cleaned[j++] = text[i];
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
    scanf("%d", &choice);
    getchar(); // Consome o '\n'

    if (choice == 1)
    {
        printf("Digite o texto a ser cifrado:\n");
        fgets(plaintext, MAX_TEXT_SIZE, stdin);
        plaintext[strcspn(plaintext, "\n")] = '\0'; // Remove o '\n' final
    }
    else if (choice == 2)
    {
        char filename[100];
        printf("Digite o nome do arquivo: ");
        fgets(filename, 100, stdin);
        filename[strcspn(filename, "\n")] = '\0'; // Remove o '\n' final

        if (!read_file(filename, plaintext, MAX_TEXT_SIZE))
        {
            return;
        }
    }
    else
    {
        printf("Opção inválida!\n");
        return;
    }

    printf("Digite a chave: ");
    fgets(key, MAX_KEY_SIZE, stdin);
    key[strcspn(key, "\n")] = '\0'; // Remove o '\n' final

    // Verifica se a chave é válida
    if (strlen(key) == 0)
    {
        printf("A chave não pode ser vazia!\n");
        return;
    }

    // Cifra o texto
    vigenere_encrypt(plaintext, key, ciphertext);

    printf("\nTexto cifrado:\n%s\n", ciphertext);

    // Pergunta se deseja salvar o texto cifrado
    printf("\nDeseja salvar o texto cifrado? (s/n): ");
    char save;
    scanf(" %c", &save);

    if (save == 's' || save == 'S')
    {
        char filename[100];
        printf("Digite o nome do arquivo: ");
        scanf("%s", filename);

        if (write_file(filename, ciphertext))
        {
            printf("Texto cifrado salvo com sucesso!\n");
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
    scanf("%d", &choice);
    getchar(); // Consome o '\n'

    if (choice == 1)
    {
        printf("Digite o texto cifrado:\n");
        fgets(ciphertext, MAX_TEXT_SIZE, stdin);
        ciphertext[strcspn(ciphertext, "\n")] = '\0'; // Remove o '\n' final
    }
    else if (choice == 2)
    {
        char filename[100];
        printf("Digite o nome do arquivo: ");
        fgets(filename, 100, stdin);
        filename[strcspn(filename, "\n")] = '\0'; // Remove o '\n' final

        if (!read_file(filename, ciphertext, MAX_TEXT_SIZE))
        {
            return;
        }
    }
    else
    {
        printf("Opção inválida!\n");
        return;
    }

    printf("Digite a chave: ");
    fgets(key, MAX_KEY_SIZE, stdin);
    key[strcspn(key, "\n")] = '\0'; // Remove o '\n' final

    // Verifica se a chave é válida
    if (strlen(key) == 0)
    {
        printf("A chave não pode ser vazia!\n");
        return;
    }

    // Decifra o texto
    vigenere_decrypt(ciphertext, key, plaintext);

    printf("\nTexto decifrado:\n%s\n", plaintext);

    // Pergunta se deseja salvar o texto decifrado
    printf("\nDeseja salvar o texto decifrado? (s/n): ");
    char save;
    scanf(" %c", &save);

    if (save == 's' || save == 'S')
    {
        char filename[100];
        printf("Digite o nome do arquivo: ");
        scanf("%s", filename);

        if (write_file(filename, plaintext))
        {
            printf("Texto decifrado salvo com sucesso!\n");
        }
    }
}

/**
 * @brief Menu para realizar o ataque de recuperação de senha
 */
void attack_menu()
{
    char ciphertext[MAX_TEXT_SIZE];
    char cleaned_text[MAX_TEXT_SIZE];
    char key[MAX_KEY_SIZE];
    char plaintext[MAX_TEXT_SIZE];
    int choice, language;

    printf("\n===== ATAQUE DE RECUPERAÇÃO DE SENHA =====\n");
    printf("Este módulo utiliza análise de frequência e Índice de Coincidência (IC)\n");
    printf("para descobrir a chave usada na cifra de Vigenère sem conhecimento prévio.\n\n");

    printf("Escolha uma opção:\n");
    printf("1. Digitar o texto cifrado\n");
    printf("2. Carregar o texto cifrado de um arquivo\n");
    printf("Opção: ");
    scanf("%d", &choice);
    getchar(); // Consome o '\n'

    if (choice == 1)
    {
        printf("Digite o texto cifrado:\n");
        fgets(ciphertext, MAX_TEXT_SIZE, stdin);
        ciphertext[strcspn(ciphertext, "\n")] = '\0'; // Remove o '\n' final
    }
    else if (choice == 2)
    {
        char filename[100];
        printf("Digite o nome do arquivo: ");
        fgets(filename, 100, stdin);
        filename[strcspn(filename, "\n")] = '\0'; // Remove o '\n' final

        if (!read_file(filename, ciphertext, MAX_TEXT_SIZE))
        {
            return;
        }
    }
    else
    {
        printf("Opção inválida!\n");
        return;
    }

    printf("\nSelecione o idioma do texto original:\n");
    printf("1. Português\n");
    printf("2. Inglês\n");
    printf("Opção: ");
    scanf("%d", &language);

    if (language != 1 && language != 2)
    {
        printf("Opção inválida!\n");
        return;
    }

    int is_portuguese = (language == 1);

    // Limpa o texto (remove caracteres não alfabéticos)
    clean_text(ciphertext, cleaned_text);

    printf("\nIniciando análise do texto cifrado...\n");
    printf("Comprimento do texto cifrado: %zu caracteres\n", strlen(ciphertext));
    printf("Comprimento do texto limpo (apenas letras): %zu caracteres\n", strlen(cleaned_text));

    // Cálculo do IC global para confirmar que é uma cifra polialfabética
    double global_ic = index_of_coincidence(cleaned_text);
    printf("\nÍndice de Coincidência (IC) global do texto cifrado: %.5f\n", global_ic);
    printf("IC esperado para texto em %s: %.5f\n",
           is_portuguese ? "português" : "inglês",
           is_portuguese ? 0.072 : 0.067);
    printf("IC típico para texto aleatório: 0.03846 (1/26)\n");

    if (global_ic > 0.065)
    {
        printf("\nAVISO: O IC global é alto, sugerindo que o texto pode não estar\n");
        printf("cifrado ou pode estar usando uma cifra monoalfabética (não Vigenère).\n");
    }
    else if (global_ic < 0.04)
    {
        printf("\nConfirmado: O IC baixo indica uma cifra polialfabética (como Vigenère).\n");
    }
    else
    {
        printf("\nO IC sugere uma cifra polialfabética, mas outros fatores podem estar\n");
        printf("influenciando o resultado (como tamanho do texto ou chave pequena).\n");
    }

    // Opção para forçar um tamanho de chave específico
    printf("\nDeseja especificar um tamanho de chave ou usar análise automática?\n");
    printf("1. Usar análise automática\n");
    printf("2. Especificar tamanho de chave\n");
    printf("Opção: ");
    int key_option;
    scanf("%d", &key_option);

    int key_length;
    if (key_option == 1)
    {
        // Encontra o tamanho mais provável da chave
        key_length = find_key_length(cleaned_text, is_portuguese);
    }
    else if (key_option == 2)
    {
        printf("Digite o tamanho da chave a ser usado: ");
        scanf("%d", &key_length);
        if (key_length <= 0 || key_length > 100)
        {
            printf("Tamanho de chave inválido. Usando análise automática.\n");
            key_length = find_key_length(cleaned_text, is_portuguese);
        }
        else
        {
            printf("Usando tamanho de chave especificado: %d\n", key_length);
        }
    }
    else
    {
        printf("Opção inválida. Usando análise automática.\n");
        key_length = find_key_length(cleaned_text, is_portuguese);
    }

    // Recupera a chave
    recover_key(cleaned_text, key_length, is_portuguese, key);
    printf("\nChave recuperada: \"%s\"\n", key);

    // Decifra o texto usando a chave recuperada
    vigenere_decrypt(ciphertext, key, plaintext);

    printf("\n===== RESULTADO FINAL =====\n");
    printf("Chave recuperada: \"%s\" (comprimento: %d)\n", key, key_length);
    printf("\nTexto decifrado:\n%s\n", plaintext);

    // Pergunta se deseja salvar o texto decifrado e um relatório
    printf("\nDeseja salvar o texto decifrado? (s/n): ");
    char save;
    scanf(" %c", &save);

    if (save == 's' || save == 'S')
    {
        char filename[100];
        printf("Digite o nome do arquivo para o texto decifrado: ");
        scanf("%s", filename);

        if (write_file(filename, plaintext))
        {
            printf("Texto decifrado salvo com sucesso em '%s'!\n", filename);
        }

        // Salva também um relatório com detalhes da análise
        char report_filename[110];
        snprintf(report_filename, sizeof(report_filename), "%s_relatorio.txt", filename);

        FILE *report = fopen(report_filename, "w");
        if (report)
        {
            fprintf(report, "RELATÓRIO DE ANÁLISE CRIPTOGRÁFICA\n");
            fprintf(report, "===============================\n\n");
            fprintf(report, "Data da análise: %s\n\n", __DATE__);
            fprintf(report, "DETALHES DA ANÁLISE:\n");
            fprintf(report, "- Idioma presumido: %s\n", is_portuguese ? "Português" : "Inglês");
            fprintf(report, "- Comprimento do texto cifrado: %zu caracteres\n", strlen(ciphertext));
            fprintf(report, "- Índice de Coincidência global: %.5f\n", global_ic);
            fprintf(report, "- Tamanho de chave detectado: %d\n", key_length);
            fprintf(report, "- Chave recuperada: \"%s\"\n\n", key);
            fprintf(report, "TEXTO DECIFRADO:\n%s\n", plaintext);
            fclose(report);

            printf("Relatório de análise salvo em '%s'!\n", report_filename);
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
        printf("\n===== CIFRA DE VIGENÈRE =====\n");
        printf("1. Cifrar mensagem\n");
        printf("2. Decifrar mensagem\n");
        printf("3. Realizar ataque de recuperação de senha\n");
        printf("0. Sair\n");
        printf("Escolha uma opção: ");
        scanf("%d", &choice);

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
            printf("Saindo...\n");
            break;
        default:
            printf("Opção inválida!\n");
        }
    } while (choice != 0);

    return 0;
}