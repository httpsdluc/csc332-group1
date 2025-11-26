/*
 * filecrypt.c - File Encryption/Decryption Tool
 * * - Encryption algorithms (AES-256-CBC, AES-256-CTR, ChaCha20, XOR)
 * - mmap() for efficient large file handling
 * - pthread support for parallel processing (CTR, ChaCha20, XOR only)
 * - Signal handling (SIGINT, SIGTERM)
 * - Secure key derivation using PBKDF2
 * - Progress reporting
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <signal.h>
#include <getopt.h>
#include <pthread.h>
#include <termios.h>
#include <stdint.h>
#include <endian.h> // Added for robust AES-CTR counter handling
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/err.h>

#define VERSION "1.0.4"
#define AES_KEY_SIZE 32
#define AES_IV_SIZE 16
#define CHACHA20_KEY_SIZE 32
#define CHACHA20_NONCE_SIZE 12
#define SALT_SIZE 16
#define PBKDF2_ITERATIONS 100000
#define CHUNK_SIZE (1024 * 1024) // 1MB chunks for threading
#define MAX_THREADS 8

// Algorithm types
typedef enum {
    ALG_AES_256_CBC,
    ALG_AES_256_CTR,
    ALG_CHACHA20,
    ALG_XOR
} Algorithm;

// Operation mode
typedef enum {
    MODE_ENCRYPT,
    MODE_DECRYPT
} Mode;

// Global state for signal handling
static volatile sig_atomic_t interrupted = 0;
static pthread_mutex_t progress_mutex = PTHREAD_MUTEX_INITIALIZER;
static size_t processed_bytes = 0;
static size_t total_bytes = 0;

// Configuration structure
typedef struct {
    char *input_file;
    char *output_file;
    char *key_file;
    char *password;
    Algorithm algorithm;
    Mode mode;
    int use_threads;
    int num_threads;
    int verbose;
    int show_progress;
} Config;

// Thread work structure
typedef struct {
    unsigned char *input;
    unsigned char *output;
    size_t offset;
    size_t length;
    unsigned char *key;
    unsigned char *iv;
    Algorithm algorithm;
    Mode mode;
    int thread_id;
    int result;
} ThreadWork;

// Function prototypes
void signal_handler(int signum);
void setup_signals(void);
void print_usage(const char *progname);
void print_version(void);
int parse_arguments(int argc, char *argv[], Config *config);
int read_password(char *buffer, size_t size);
int read_key_file(const char *filename, unsigned char *key);
int derive_key(const char *password, unsigned char *salt, 
               unsigned char *key, unsigned char *iv);
int encrypt_file(Config *config);
int decrypt_file(Config *config);
void *process_chunk(void *arg);
int aes_cbc_encrypt(unsigned char *plaintext, int plaintext_len,
                    unsigned char *key, unsigned char *iv,
                    unsigned char *ciphertext);
int aes_cbc_decrypt(unsigned char *ciphertext, int ciphertext_len,
                    unsigned char *key, unsigned char *iv,
                    unsigned char *plaintext);
int aes_ctr_process(unsigned char *input, int input_len,
                    unsigned char *key, unsigned char *iv, size_t block_offset,
                    unsigned char *output);
int chacha20_process(unsigned char *input, int input_len,
                     unsigned char *key, unsigned char *nonce, size_t counter_offset,
                     unsigned char *output);
void xor_cipher(unsigned char *data, size_t len, unsigned char *key, size_t key_len);
void update_progress(size_t bytes);
void print_progress(void);
void cleanup_openssl(void);

// Signal handler for interruption
void signal_handler(int signum) {
    interrupted = 1;
    fprintf(stderr, "\n\nReceived signal %d, cleaning up...\n", signum);
}

void setup_signals(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
}

void print_usage(const char *progname) {
    printf("Usage: %s [OPTIONS]\n\n", progname);
    printf("Options:\n");
    printf("  -e, --encrypt           Encrypt mode (default)\n");
    printf("  -d, --decrypt           Decrypt mode\n");
    printf("  -i, --input FILE        Input file path (required)\n");
    printf("  -o, --output FILE       Output file path (required)\n");
    printf("  -p, --password PASS     Password (prompt if not provided)\n");
    printf("  -k, --keyfile FILE      Key file path (alternative to password)\n");
    printf("  -a, --algorithm ALG     Algorithm: aes256-cbc (default), aes256-ctr, chacha20, xor\n");
    printf("  -t, --threads NUM       Use NUM threads (default: 1, max: %d)\n", MAX_THREADS);
    printf("                          Note: Threading only supported for aes256-ctr, chacha20, and xor\n");
    printf("  -v, --verbose           Verbose output\n");
    printf("  -P, --progress          Show progress bar\n");
    printf("  -V, --version           Print version information\n");
    printf("  -h, --help              Display this help message\n\n");
    printf("Examples:\n");
    printf("  %s -e -i file.txt -o file.enc\n", progname);
    printf("  %s -d -i file.enc -o file.txt -t 4\n", progname);
    printf("  %s -e -i large.bin -o large.enc -a aes256-ctr -t 4 -P\n", progname);
}

void print_version(void) {
    printf("filecrypt version %s\n", VERSION);
    printf("OpenSSL version: %s\n", OPENSSL_VERSION_TEXT);
}



int read_password(char *buffer, size_t size) {
    struct termios old_term, new_term;
    
    // Turn off echo
    if (tcgetattr(STDIN_FILENO, &old_term) != 0) {
        fprintf(stderr, "Error getting terminal attributes\n");
        return -1;
    }
    
    new_term = old_term;
    new_term.c_lflag &= ~ECHO;
    
    if (tcsetattr(STDIN_FILENO, TCSANOW, &new_term) != 0) {
        fprintf(stderr, "Error setting terminal attributes\n");
        return -1;
    }
    
    printf("Enter password: ");
    fflush(stdout);
    
    if (fgets(buffer, size, stdin) == NULL) {
        tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
        fprintf(stderr, "\nError reading password\n");
        return -1;
    }
    
    // Restore terminal
    tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
    printf("\n");
    
    // Remove newline
    size_t len = strlen(buffer);
    if (len > 0 && buffer[len-1] == '\n') {
        buffer[len-1] = '\0';
    }
    
    if (strlen(buffer) == 0) {
        fprintf(stderr, "Error: Empty password\n");
        return -1;
    }
    
    return 0;
}

int read_key_file(const char *filename, unsigned char *key) {
    FILE *f = fopen(filename, "rb");
    if (!f) {
        fprintf(stderr, "Error opening key file '%s': %s\n", filename, strerror(errno));
        return -1;
    }
    
    if (fread(key, 1, AES_KEY_SIZE, f) != AES_KEY_SIZE) {
        fprintf(stderr, "Error: Key file too small (needs 32 bytes)\n");
        fclose(f);
        return -1;
    }
    
    fclose(f);
    return 0;
}

int derive_key(const char *password, unsigned char *salt,
               unsigned char *key, unsigned char *iv) {
    unsigned char derived[AES_KEY_SIZE + AES_IV_SIZE];
    
    if (!PKCS5_PBKDF2_HMAC(password, strlen(password),
                           salt, SALT_SIZE,
                           PBKDF2_ITERATIONS,
                           EVP_sha256(),
                           AES_KEY_SIZE + AES_IV_SIZE,
                           derived)) {
        fprintf(stderr, "Error: Key derivation failed\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    
    memcpy(key, derived, AES_KEY_SIZE);
    memcpy(iv, derived + AES_KEY_SIZE, AES_IV_SIZE);
    
    // Clear sensitive data
    memset(derived, 0, sizeof(derived));
    
    return 0;
}

void xor_cipher(unsigned char *data, size_t len, unsigned char *key, size_t key_len) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key[i % key_len];
    }
}



int aes_cbc_encrypt(unsigned char *plaintext, int plaintext_len,
                    unsigned char *key, unsigned char *iv,
                    unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;
    
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len = len;
    
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;
    
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}



int aes_cbc_decrypt(unsigned char *ciphertext, int ciphertext_len,
                    unsigned char *key, unsigned char *iv,
                    unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;
    
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len += len;
    
    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}



int aes_ctr_process(unsigned char *input, int input_len,
                    unsigned char *key, unsigned char *base_iv, size_t block_offset,
                    unsigned char *output) {
    EVP_CIPHER_CTX *ctx;
    int len;
    unsigned char iv[AES_IV_SIZE];
    
    // FIX: Using robust 64-bit integer arithmetic for counter increment
    memcpy(iv, base_iv, AES_IV_SIZE);
    
    // Access the counter part (last 8 bytes) as a 64-bit integer
    // Note: OpenSSL expects big-endian counter
    uint64_t *counter_ptr = (uint64_t *)(iv + 8);
    uint64_t current_counter = be64toh(*counter_ptr);
    
    // Add offset (convert bytes to 16-byte blocks)
    current_counter += (block_offset / 16);
    
    // Write back in big-endian
    *counter_ptr = htobe64(current_counter);
    
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    if (1 != EVP_EncryptUpdate(ctx, output, &len, input, input_len)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    EVP_CIPHER_CTX_free(ctx);
    return len;
}



int chacha20_process(unsigned char *input, int input_len,
                     unsigned char *key, unsigned char *nonce, size_t counter_offset,
                     unsigned char *output) {
    EVP_CIPHER_CTX *ctx;
    int len;
    unsigned char iv[16] = {0};
    
    // ChaCha20 uses a 32-bit counter + 96-bit nonce 
    // Counter starts at counter_offset / 64 (64 bytes per ChaCha20 block)
    uint32_t counter = counter_offset / 64;
    memcpy(iv, &counter, 4);
    memcpy(iv + 4, nonce, CHACHA20_NONCE_SIZE);
    
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    
    if (1 != EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, key, iv)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    if (1 != EVP_EncryptUpdate(ctx, output, &len, input, input_len)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    EVP_CIPHER_CTX_free(ctx);
    return len;
}

void update_progress(size_t bytes) {
    pthread_mutex_lock(&progress_mutex);
    processed_bytes += bytes;
    pthread_mutex_unlock(&progress_mutex);
}

void print_progress(void) {
    pthread_mutex_lock(&progress_mutex);
    if (total_bytes > 0) {
        int percent = (int)((processed_bytes * 100) / total_bytes);
        printf("\rProgress: [");
        for (int i = 0; i < 50; i++) {
            if (i < percent / 2) {
                printf("=");
            } else if (i == percent / 2) {
                printf(">");
            } else {
                printf(" ");
            }
        }
        printf("] %d%% (%zu/%zu bytes)", percent, processed_bytes, total_bytes);
        fflush(stdout);
    }
    pthread_mutex_unlock(&progress_mutex);
}

void *process_chunk(void *arg) {
    ThreadWork *work = (ThreadWork *)arg;
    
    if (interrupted) {
        work->result = -1;
        return NULL;
    }
    
    work->result = 0;
    
    if (work->algorithm == ALG_XOR) {
        unsigned char *temp = malloc(work->length);
        if (!temp) {
            work->result = -1;
            return NULL;
        }
        memcpy(temp, work->input + work->offset, work->length);
        xor_cipher(temp, work->length, work->key, AES_KEY_SIZE);
        memcpy(work->output + work->offset, temp, work->length);
        free(temp);
    } else if (work->algorithm == ALG_AES_256_CTR) {
        int result = aes_ctr_process(work->input + work->offset, work->length,
                                     work->key, work->iv, work->offset,
                                     work->output + work->offset);
        if (result < 0) {
            work->result = -1;
            return NULL;
        }
    } else if (work->algorithm == ALG_CHACHA20) {
        int result = chacha20_process(work->input + work->offset, work->length,
                                      work->key, work->iv, work->offset,
                                      work->output + work->offset);
        if (result < 0) {
            work->result = -1;
            return NULL;
        }
    }
    
    update_progress(work->length);
    
    return NULL;
}



// Encryption and Decryption!!! -------------------------------------------------------------------------------------------------------------------
int encrypt_file(Config *config) {
    int input_fd, output_fd;
    struct stat st;
    unsigned char *input_map = NULL;
    unsigned char *output_map = NULL;
    unsigned char key[AES_KEY_SIZE];
    unsigned char iv[AES_IV_SIZE];
    unsigned char salt[SALT_SIZE];
    size_t file_size;
    int result = -1;
    
    // Validate threading support
    if (config->use_threads && config->num_threads > 1 && 
        config->algorithm == ALG_AES_256_CBC) {
        if (config->verbose) {
            fprintf(stderr, "Warning: Multi-threading not supported for AES-CBC. Using single thread.\n");
        }
        config->num_threads = 1;
        config->use_threads = 0;
    }
    
    // Open input file
    input_fd = open(config->input_file, O_RDONLY);
    if (input_fd == -1) {
        fprintf(stderr, "Error opening input file '%s': %s\n",
                config->input_file, strerror(errno));
        return -1;
    }
    
    // Get file size
    if (fstat(input_fd, &st) == -1) {
        fprintf(stderr, "Error stating input file: %s\n", strerror(errno));
        close(input_fd);
        return -1;
    }
    file_size = st.st_size;
    total_bytes = file_size;
    
    if (config->verbose) {
        printf("Input file size: %zu bytes\n", file_size);
    }
    
    // Handle Key derivation (Password vs Keyfile)
    if (config->key_file) {
        // Mode 1: Keyfile
        if (read_key_file(config->key_file, key) != 0) {
            close(input_fd);
            return -1;
        }
        // For Keyfile mode, we MUST generate a random IV and Salt (Salt is just to fill header)
        if (RAND_bytes(salt, SALT_SIZE) != 1 || RAND_bytes(iv, AES_IV_SIZE) != 1) {
            fprintf(stderr, "Error generating random data\n");
            ERR_print_errors_fp(stderr);
            close(input_fd);
            return -1;
        }
    } else {
        // Mode 2: Password
        if (RAND_bytes(salt, SALT_SIZE) != 1) {
            fprintf(stderr, "Error generating random salt\n");
            ERR_print_errors_fp(stderr);
            close(input_fd);
            return -1;
        }
        if (derive_key(config->password, salt, key, iv) != 0) {
            close(input_fd);
            return -1;
        }
    }
    
    // Handle empty file case BEFORE mapping (oopsies)
    if (file_size == 0) {
        // Create output file with just the header
        output_fd = open(config->output_file, O_RDWR | O_CREAT | O_TRUNC, 0600);
        if (output_fd == -1) {
            fprintf(stderr, "Error creating output file '%s': %s\n",
                    config->output_file, strerror(errno));
            memset(key, 0, sizeof(key));
            memset(iv, 0, sizeof(iv));
            close(input_fd);
            return -1;
        }
        
        // Write header for empty file
        uint64_t file_size_64 = 0;
        if (write(output_fd, salt, SALT_SIZE) != SALT_SIZE ||
            write(output_fd, iv, AES_IV_SIZE) != AES_IV_SIZE ||
            write(output_fd, &file_size_64, sizeof(uint64_t)) != sizeof(uint64_t)) {
            fprintf(stderr, "Error writing header: %s\n", strerror(errno));
            memset(key, 0, sizeof(key));
            memset(iv, 0, sizeof(iv));
            close(output_fd);
            close(input_fd);
            return -1;
        }
        
        if (config->verbose) {
            printf("Encryption completed successfully (empty file)\n");
        }
        
        memset(key, 0, sizeof(key));
        memset(iv, 0, sizeof(iv));
        close(output_fd);
        close(input_fd);
        return 0;
    }
    
    // Map input file to memory (only for non-empty files)
    input_map = mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, input_fd, 0);
    if (input_map == MAP_FAILED) {
        fprintf(stderr, "Error mapping input file: %s\n", strerror(errno));
        fprintf(stderr, "File: %s, Size: %zu\n", config->input_file, file_size);
        memset(key, 0, sizeof(key));
        memset(iv, 0, sizeof(iv));
        close(input_fd);
        return -1;
    }
    madvise(input_map, file_size, MADV_SEQUENTIAL);
    
    // Create and open output file
    output_fd = open(config->output_file, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (output_fd == -1) {
        fprintf(stderr, "Error creating output file '%s': %s\n",
                config->output_file, strerror(errno));
        if (input_map) munmap(input_map, file_size);
        close(input_fd);
        return -1;
    }
    
    // Write header: salt + IV + file size (uint64_t for portability)
    uint64_t file_size_64 = file_size;
    size_t header_size = SALT_SIZE + AES_IV_SIZE + sizeof(uint64_t);
    
    if (write(output_fd, salt, SALT_SIZE) != SALT_SIZE ||
        write(output_fd, iv, AES_IV_SIZE) != AES_IV_SIZE ||
        write(output_fd, &file_size_64, sizeof(uint64_t)) != sizeof(uint64_t)) {
        fprintf(stderr, "Error writing header: %s\n", strerror(errno));
        goto cleanup_encrypt;
    }
    
    if (config->verbose) {
        const char *alg_name = (config->algorithm == ALG_AES_256_CBC) ? "AES-256-CBC" :
                               (config->algorithm == ALG_AES_256_CTR) ? "AES-256-CTR" :
                               (config->algorithm == ALG_CHACHA20) ? "ChaCha20" : "XOR";
        printf("Encrypting with %s", alg_name);
        if (config->use_threads && config->num_threads > 1) {
            printf(" (using %d threads)", config->num_threads);
        }
        printf("...\n");
    }
    
    // Handle different algorithms
    if (config->algorithm == ALG_AES_256_CBC) {
        // AES CBC - single threaded
        size_t output_size = file_size + EVP_CIPHER_block_size(EVP_aes_256_cbc());
        unsigned char *output_buffer = malloc(output_size);
        if (!output_buffer) {
            fprintf(stderr, "Error allocating output buffer\n");
            goto cleanup_encrypt;
        }
        
        int encrypted_len = aes_cbc_encrypt(input_map, file_size, key, iv, output_buffer);
        if (encrypted_len < 0) {
            fprintf(stderr, "Encryption failed\n");
            free(output_buffer);
            goto cleanup_encrypt;
        }
        
        if (write(output_fd, output_buffer, encrypted_len) != encrypted_len) {
            fprintf(stderr, "Error writing encrypted data: %s\n", strerror(errno));
            free(output_buffer);
            goto cleanup_encrypt;
        }
        
        free(output_buffer);
        processed_bytes = file_size;
        
    } else {
        // For CTR, ChaCha20, and XOR - can use threading
        size_t output_size = file_size; // No padding for stream ciphers
        
        if (ftruncate(output_fd, header_size + output_size) == -1) {
            fprintf(stderr, "Error allocating output file: %s\n", strerror(errno));
            goto cleanup_encrypt;
        }
        
        output_map = mmap(NULL, header_size + output_size, PROT_READ | PROT_WRITE,
                          MAP_SHARED, output_fd, 0);
        if (output_map == MAP_FAILED) {
            fprintf(stderr, "Error mapping output file: %s\n", strerror(errno));
            goto cleanup_encrypt;
        }
        
        if (config->use_threads && config->num_threads > 1 && file_size > CHUNK_SIZE) {
            // Multi-threaded processing
            pthread_t threads[MAX_THREADS];
            ThreadWork works[MAX_THREADS];
            
            size_t chunk_size = file_size / config->num_threads;
            if (chunk_size == 0) chunk_size = file_size;
            
            int num_threads_used = (file_size + chunk_size - 1) / chunk_size;
            if (num_threads_used > config->num_threads) {
                num_threads_used = config->num_threads;
            }
            
            for (int i = 0; i < num_threads_used; i++) {
                works[i].input = input_map;
                works[i].output = output_map + header_size;
                works[i].offset = i * chunk_size;
                works[i].length = (i == num_threads_used - 1) ? 
                                  (file_size - i * chunk_size) : chunk_size;
                works[i].key = key;
                works[i].iv = iv;
                works[i].algorithm = config->algorithm;
                works[i].mode = MODE_ENCRYPT;
                works[i].thread_id = i;
                
                if (pthread_create(&threads[i], NULL, process_chunk, &works[i]) != 0) {
                    fprintf(stderr, "Error creating thread %d\n", i);
                    goto cleanup_encrypt;
                }
            }
            
            // Show progress
            if (config->show_progress) {
                while (processed_bytes < total_bytes && !interrupted) {
                    print_progress();
                    usleep(100000); // 100ms
                }
            }
            
            // Wait for all threads
            for (int i = 0; i < num_threads_used; i++) {
                pthread_join(threads[i], NULL);
                if (works[i].result != 0) {
                    fprintf(stderr, "Thread %d failed\n", i);
                    goto cleanup_encrypt;
                }
            }
            
        } else {
            // Single-threaded processing
            if (config->algorithm == ALG_XOR) {
                memcpy(output_map + header_size, input_map, file_size);
                xor_cipher(output_map + header_size, file_size, key, AES_KEY_SIZE);
            } else if (config->algorithm == ALG_AES_256_CTR) {
                if (aes_ctr_process(input_map, file_size, key, iv, 0, 
                                   output_map + header_size) < 0) {
                    fprintf(stderr, "Encryption failed\n");
                    goto cleanup_encrypt;
                }
            } else if (config->algorithm == ALG_CHACHA20) {
                if (chacha20_process(input_map, file_size, key, iv, 0,
                                    output_map + header_size) < 0) {
                    fprintf(stderr, "Encryption failed\n");
                    goto cleanup_encrypt;
                }
            }
            processed_bytes = file_size;
        }
        
        if (output_map && output_map != MAP_FAILED) {
            msync(output_map, header_size + output_size, MS_SYNC);
        }
    }
    
    if (config->show_progress) {
        print_progress();
        printf("\n");
    }
    
    result = 0;
    if (config->verbose) {
        printf("Encryption completed successfully\n");
    }
    
cleanup_encrypt:
    // Clear sensitive data
    memset(key, 0, sizeof(key));
    memset(iv, 0, sizeof(iv));
    
    if (output_map && output_map != MAP_FAILED) {
        munmap(output_map, header_size + file_size);
    }
    if (input_map && input_map != MAP_FAILED) {
        munmap(input_map, file_size);
    }
    close(output_fd);
    close(input_fd);
    
    return result;
}



int decrypt_file(Config *config) {
    int input_fd, output_fd;
    struct stat st;
    unsigned char *input_map = NULL;
    unsigned char *output_map = NULL;
    unsigned char key[AES_KEY_SIZE];
    unsigned char iv[AES_IV_SIZE];
    unsigned char salt[SALT_SIZE];
    uint64_t file_size_64;
    size_t file_size, original_size;
    int result = -1;

    // Open input file
    input_fd = open(config->input_file, O_RDONLY);
    if (input_fd == -1) {
        fprintf(stderr, "Error opening input file '%s': %s\n",
                config->input_file, strerror(errno));
        return -1;
    }

    // Get file size
    if (fstat(input_fd, &st) == -1) {
        fprintf(stderr, "Error stating input file: %s\n", strerror(errno));
        close(input_fd);
        return -1;
    }
    file_size = st.st_size;

    size_t header_size = SALT_SIZE + AES_IV_SIZE + sizeof(uint64_t);
    if (file_size < header_size) {
        fprintf(stderr, "Error: File too small to be encrypted\n");
        close(input_fd);
        return -1;
    }

    // Read header
    if (read(input_fd, salt, SALT_SIZE) != SALT_SIZE ||
        read(input_fd, iv, AES_IV_SIZE) != AES_IV_SIZE ||
        read(input_fd, &file_size_64, sizeof(uint64_t)) != sizeof(uint64_t)) {
        fprintf(stderr, "Error reading header: %s\n", strerror(errno));
        close(input_fd);
        return -1;
    }

    original_size = file_size_64;

    // Handle Key derivation (Password vs Keyfile)
    if (config->key_file) {
        if (read_key_file(config->key_file, key) != 0) {
            close(input_fd);
            return -1;
        }
        // Note: For keyfile mode, we use the IV read from the file header directly.
        // We do NOT overwrite it.
    } else {
        // Mode 2: Password
        // For password mode, we normally derive key AND IV.
        // Current implementation logic implies the IV in the file is the derived IV.
        // So we can overwrite 'iv' with the derived one, or use a temp buffer.
        // To be safe and consistent with previous logic, we let it derive.
        // NOTE: In standard password derivation, usually IV is random and Key is derived. 
        // But this tool's password mode derives both. 
        unsigned char derived_iv[AES_IV_SIZE];
        if (derive_key(config->password, salt, key, derived_iv) != 0) {
            close(input_fd);
            return -1;
        }
        // Use the derived IV, as that's how it was encrypted in Password mode
        memcpy(iv, derived_iv, AES_IV_SIZE);
    }

    // Handle empty file
    if (original_size == 0) {
        output_fd = open(config->output_file, O_RDWR | O_CREAT | O_TRUNC, 0600);
        if (output_fd == -1) {
            fprintf(stderr, "Error creating output file '%s': %s\n",
                    config->output_file, strerror(errno));
            close(input_fd);
            return -1;
        }
        close(output_fd);
        close(input_fd);
        if (config->verbose) {
            printf("Decryption completed successfully (empty file)\n");
        }
        return 0;
    }

    // Map encrypted data with page-aligned offset
    size_t encrypted_size = file_size - header_size;
    long pagesize = sysconf(_SC_PAGE_SIZE);
    off_t offset_aligned = (header_size / pagesize) * pagesize;
    size_t map_len = encrypted_size + (header_size - offset_aligned);

    input_map = mmap(NULL, map_len, PROT_READ, MAP_PRIVATE, input_fd, offset_aligned);
    if (input_map == MAP_FAILED) {
        fprintf(stderr, "Error mapping input file: %s\n", strerror(errno));
        close(input_fd);
        return -1;
    }

    unsigned char *encrypted_data = input_map + (header_size - offset_aligned);

    // Create output file
    output_fd = open(config->output_file, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (output_fd == -1) {
        fprintf(stderr, "Error creating output file '%s': %s\n",
                config->output_file, strerror(errno));
        munmap(input_map, map_len);
        close(input_fd);
        return -1;
    }

    if (config->algorithm == ALG_AES_256_CBC) {
        unsigned char *output_buffer = malloc(encrypted_size);
        if (!output_buffer) {
            fprintf(stderr, "Error allocating output buffer\n");
            goto cleanup;
        }

        int decrypted_len = aes_cbc_decrypt(encrypted_data, encrypted_size, key, iv, output_buffer);
        if (decrypted_len < 0) {
            fprintf(stderr, "Decryption failed - wrong password or corrupted file\n");
            free(output_buffer);
            goto cleanup;
        }

        if (write(output_fd, output_buffer, decrypted_len) != decrypted_len) {
            fprintf(stderr, "Error writing decrypted data: %s\n", strerror(errno));
            free(output_buffer);
            goto cleanup;
        }

        free(output_buffer);
    } else {
        // Handle CTR, ChaCha20, XOR (unchanged)
        if (ftruncate(output_fd, original_size) == -1) {
            fprintf(stderr, "Error allocating output file: %s\n", strerror(errno));
            goto cleanup;
        }

        output_map = mmap(NULL, original_size, PROT_READ | PROT_WRITE,
                          MAP_SHARED, output_fd, 0);
        if (output_map == MAP_FAILED) {
            fprintf(stderr, "Error mapping output file: %s\n", strerror(errno));
            goto cleanup;
        }

        // For simplicity, single-threaded
        if (config->algorithm == ALG_XOR) {
            memcpy(output_map, encrypted_data, original_size);
            xor_cipher(output_map, original_size, key, AES_KEY_SIZE);
        } else if (config->algorithm == ALG_AES_256_CTR) {
            if (aes_ctr_process(encrypted_data, original_size, key, iv, 0, output_map) < 0) {
                fprintf(stderr, "Decryption failed\n");
                goto cleanup;
            }
        } else if (config->algorithm == ALG_CHACHA20) {
            if (chacha20_process(encrypted_data, original_size, key, iv, 0, output_map) < 0) {
                fprintf(stderr, "Decryption failed\n");
                goto cleanup;
            }
        }

        msync(output_map, original_size, MS_SYNC);
    }

    if (config->verbose) {
        printf("Decrypted file size: %zu bytes\n", original_size);
        printf("Decryption completed successfully\n");
    }
    result = 0;

cleanup:
    memset(key, 0, sizeof(key));
    memset(iv, 0, sizeof(iv));

    if (output_map && output_map != MAP_FAILED) {
        munmap(output_map, original_size);
    }
    if (input_map && input_map != MAP_FAILED) {
        munmap(input_map, map_len);
    }

    close(output_fd);
    close(input_fd);
    return result;
}



// Pass arguments!!! ----------------------------------------------------------------------------------------------------------
int parse_arguments(int argc, char *argv[], Config *config) {
    int opt;
    static struct option long_options[] = {
        {"encrypt",   no_argument,       0, 'e'},
        {"decrypt",   no_argument,       0, 'd'},
        {"input",     required_argument, 0, 'i'},
        {"output",    required_argument, 0, 'o'},
        {"password",  required_argument, 0, 'p'},
        {"keyfile",   required_argument, 0, 'k'},
        {"algorithm", required_argument, 0, 'a'},
        {"threads",   required_argument, 0, 't'},
        {"verbose",   no_argument,       0, 'v'},
        {"progress",  no_argument,       0, 'P'},
        {"version",   no_argument,       0, 'V'},
        {"help",      no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };
    
    // Set defaults
    memset(config, 0, sizeof(Config));
    config->mode = MODE_ENCRYPT;
    config->algorithm = ALG_AES_256_CBC;
    config->num_threads = 1;
    config->verbose = 0;
    config->show_progress = 0;
    config->use_threads = 0;
    
    while ((opt = getopt_long(argc, argv, "edi:o:p:k:a:t:vPVh", long_options, NULL)) != -1) {
        switch (opt) {
            case 'e':
                config->mode = MODE_ENCRYPT;
                break;
            case 'd':
                config->mode = MODE_DECRYPT;
                break;
            case 'i':
                config->input_file = strdup(optarg);
                break;
            case 'o':
                config->output_file = strdup(optarg);
                break;
            case 'p':
                config->password = strdup(optarg);
                break;
            case 'k':
                config->key_file = strdup(optarg);
                break;
            case 'a':
                if (strcmp(optarg, "aes256-cbc") == 0 || strcmp(optarg, "aes256") == 0 || strcmp(optarg, "aes-cbc") == 0) {
                    config->algorithm = ALG_AES_256_CBC;
                } else if (strcmp(optarg, "aes256-ctr") == 0 || strcmp(optarg, "aes-ctr") == 0) {
                    config->algorithm = ALG_AES_256_CTR;
                } else if (strcmp(optarg, "chacha20") == 0) {
                    config->algorithm = ALG_CHACHA20;
                } else if (strcmp(optarg, "xor") == 0) {
                    config->algorithm = ALG_XOR;
                } else {
                    fprintf(stderr, "Unknown algorithm: %s\n", optarg);
                    fprintf(stderr, "Valid algorithms: aes256-cbc, aes256-ctr, chacha20, xor\n");
                    return -1;
                }
                break;
            case 't':
                config->num_threads = atoi(optarg);
                if (config->num_threads < 1 || config->num_threads > MAX_THREADS) {
                    fprintf(stderr, "Thread count must be between 1 and %d\n", MAX_THREADS);
                    return -1;
                }
                config->use_threads = (config->num_threads > 1);
                break;
            case 'v':
                config->verbose = 1;
                break;
            case 'P':
                config->show_progress = 1;
                break;
            case 'V':
                print_version();
                exit(0);
            case 'h':
                print_usage(argv[0]);
                exit(0);
            default:
                print_usage(argv[0]);
                return -1;
        }
    }
    
    // Validate required arguments
    if (!config->input_file || !config->output_file) {
        fprintf(stderr, "Error: Input and output files are required\n\n");
        print_usage(argv[0]);
        return -1;
    }
    
    // Get password if not provided
    if (!config->password && !config->key_file) {
        char pass_buffer[256];
        if (read_password(pass_buffer, sizeof(pass_buffer)) != 0) {
            return -1;
        }
        config->password = strdup(pass_buffer);
        memset(pass_buffer, 0, sizeof(pass_buffer));
    }
    
    return 0;
}

void cleanup_openssl(void) {
    EVP_cleanup();
    ERR_free_strings();
}



// Main!!! ---------------------------------------------------------------------------------------------------------------
int main(int argc, char *argv[]) {
    Config config = {0};
    int result;
    
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    
    // Setup signal handlers
    setup_signals();
    
    // Parse arguments
    if (parse_arguments(argc, argv, &config) != 0) {
        return 1;
    }
    
    // Perform operation
    if (config.mode == MODE_ENCRYPT) {
        result = encrypt_file(&config);
    } else {
        result = decrypt_file(&config);
    }
    
    // Cleanup
    if (config.password) {
        memset(config.password, 0, strlen(config.password));
        free(config.password);
    }
    free(config.input_file);
    free(config.output_file);
    free(config.key_file);
    
    cleanup_openssl();
    
    if (interrupted) {
        fprintf(stderr, "Operation interrupted by user\n");
        return 130; // Standard exit code for SIGINT
    }
    
    return result == 0 ? 0 : 1;
}