// features i used:
//count total lines in a log file
//count lines containing a specific keyword (-k)
//count number of INFO/WARN/ERROR messages (-l)
//Ctrl+C (SIGINT) handling
//mmap() for fast file reading
//getopt() for proper command-line option parsing


#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <signal.h>
#include <string.h>
#include <errno.h>


// globals:
// flag is set to 1 when Ctrl+C (SIGINT) is received
// program checks this flag during analysis and exits cleanly
static volatile sig_atomic_t stop_flag = 0;


// signal handler:
// handle_sigint called when user presses Ctrl+C
// we dont exit here, just set a flag so the main loop can stop 
static void handle_sigint(int sig) {
    (void)sig;          // suppress unused variable warning
    stop_flag = 1;      // tell main loop to stop
}


// usage message:


// print_usage: display help message and usage instructions
static void print_usage(const char *progname) {
    fprintf(stderr,
        "Usage: %s -f <logfile> [-k <keyword>] [-l] [-h]\n"
        "\n"
        "Options:\n"
        "  -f <logfile>   Path to log file to analyze (required).\n"
        "  -k <keyword>   Count lines containing this keyword.\n"
        "  -l             Count INFO/WARN/ERROR lines.\n"
        "  -h             Show help message and exit.\n",
        progname);
}


// helper to check if a line contains a keyword


// simple substring search inside a line from mmap buffer
static int line_contains_keyword(const char *line_start, size_t len, const char *keyword) {
    size_t klen = strlen(keyword);

    if (klen == 0 || len < klen) {
        return 0; // keyword longer than line then cannot match
    }

    // manual substring search 
    for (size_t i = 0; i + klen <= len; i++) {
        if (memcmp(line_start + i, keyword, klen) == 0) {
            return 1;
        }
    }
    return 0;
}


// main program:


int main(int argc, char *argv[]) {


    // Command-line option variables

    const char *logfile = NULL;   // required
    const char *keyword = NULL;   // optional
    int count_levels = 0;         // optional (-l)


    // parse command-line arguments using getopt()

    int opt;
    while ((opt = getopt(argc, argv, "f:k:lh")) != -1) {
        switch (opt) {
            case 'f':
                logfile = optarg;
                break;
            case 'k':
                keyword = optarg;
                break;
            case 'l':
                count_levels = 1;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    // check if -f was provided
    if (logfile == NULL) {
        fprintf(stderr, "Error: -f <logfile> is required.\n");
        print_usage(argv[0]);
        return 1;
    }


    // install SIGINT handler using sigaction()

    struct sigaction sa;
    sa.sa_handler = handle_sigint;    // function above
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if (sigaction(SIGINT, &sa, NULL) == -1) {
        perror("sigaction");
        return 1;
    }


    // open the log file

    int fd = open(logfile, O_RDONLY);
    if (fd == -1) {
        perror("open");
        return 1;
    }


    // get file size with fstat()

    struct stat st;
    if (fstat(fd, &st) == -1) {
        perror("fstat");
        close(fd);      // cleanup
        return 1;
    }

    if (st.st_size == 0) {
        fprintf(stderr, "Warning: log file is empty.\n");
        close(fd);
        return 0;
    }

    size_t filesize = (size_t)st.st_size;


    // use mmap() to map entire file into memory

    // mmap is much faster than repeatedly calling read()
    // cause it lets the OS load file pages on demand
    char *map = mmap(NULL, filesize, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return 1;
    }

 
    // counters for stats

    size_t total_lines = 0;
    size_t keyword_lines = 0;
    size_t info_lines = 0;
    size_t warn_lines = 0;
    size_t error_lines = 0;


    // iterate through the mapped buffer and find line boundaries

    size_t pos = 0;
    size_t line_start = 0;

    while (pos < filesize) {

        // if Ctrl+C pressed then break early
        if (stop_flag) {
            fprintf(stderr, "\nInterrupted by user (SIGINT). Stopping analysis.\n");
            break;
        }

        char c = map[pos];
        int end_of_line = 0;

        // end of line if newline is found
        if (c == '\n') {
            end_of_line = 1;
        }
        // last line may not end with '\n'
        else if (pos == filesize - 1) {
            end_of_line = 1;
            pos++; // include last character
        }

        // process the completed line
        if (end_of_line) {

            size_t line_end = (c == '\n') ? pos : pos;
            size_t line_len = (line_end >= line_start) ? (line_end - line_start) : 0;
            const char *line_ptr = map + line_start;

            total_lines++;

            // if keyword was requested
            if (keyword != NULL &&
                line_contains_keyword(line_ptr, line_len, keyword)) {
                keyword_lines++;
            }

            // if -l option was used, count INFO/WARN/ERROR
            if (count_levels) {
                if (line_contains_keyword(line_ptr, line_len, "INFO")) {
                    info_lines++;
                }
                if (line_contains_keyword(line_ptr, line_len, "WARN")) {
                    warn_lines++;
                }
                if (line_contains_keyword(line_ptr, line_len, "ERROR")) {
                    error_lines++;
                }
            }

            // move start to next line
            line_start = pos + 1;
        }

        pos++;
    }


    // print final results

    printf("Log file: %s\n", logfile);
    printf("Total bytes: %zu\n", filesize);
    printf("Total lines: %zu\n", total_lines);

    if (keyword != NULL) {
        printf("Lines containing \"%s\": %zu\n", keyword, keyword_lines);
    }

    if (count_levels) {
        printf("INFO lines:  %zu\n", info_lines);
        printf("WARN lines:  %zu\n", warn_lines);
        printf("ERROR lines: %zu\n", error_lines);
    }


    // cleanup: unmap and close file

    if (munmap(map, filesize) == -1) {
        perror("munmap");
    }
    if (close(fd) == -1) {
        perror("close");
        return 1;
    }

    return 0;
}
