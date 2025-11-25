/*
 * memview.c - Displays detailed memory usage of a process or system
 * 
 * DESCRIPTION:
 *   This program reads memory information from the Linux /proc filesystem
 *   and displays it in a human-readable format. It demonstrates key systems
 *   programming concepts including file I/O, signal handling, and process
 *   information retrieval.
 * 
 * FEATURES:
 *   - View memory statistics (VmSize, VmRSS, etc.)
 *   - View memory maps (address ranges, permissions, mapped files)
 *   - Real-time monitoring mode
 *   - Signal handling for graceful shutdown
 * 
 * USAGE:
 *   ./memview [OPTIONS] [PID]
 *   ./memview -s          # Show memory statistics
 *   ./memview -m          # Show memory maps
 *   ./memview -r          # Real-time monitoring
 *   ./memview 1234        # View process 1234
 * 
 * AUTHOR: Arsenii Chan
 * DATE: November 2025
 */

/* === HEADER FILES === */
#include <stdio.h>      /* printf, fprintf, fopen, fgets, sscanf */
#include <stdlib.h>     /* exit, atoi */
#include <string.h>     /* strcmp, strncmp, memset, strlen */
#include <unistd.h>     /* getpid, access, sleep */
#include <sys/stat.h>   /* file status (not used directly but good practice) */
#include <fcntl.h>      /* file control options */
#include <errno.h>      /* errno, strerror - for error handling */
#include <getopt.h>     /* getopt_long - for parsing command-line options */
#include <signal.h>     /* sigaction, signal handling */

/* === CONSTANTS === 
 * Using bit flags to track which display options are enabled.
 * This allows combining multiple options with bitwise OR (|).
 */
#define SHOW_MAPS       (1 << 0)    /* 0001 - Show memory maps */
#define SHOW_STATUS     (1 << 1)    /* 0010 - Show memory status */
#define SHOW_SUMMARY    (1 << 2)    /* 0100 - Show summary (default) */
#define REALTIME_MODE   (1 << 4)    /* 10000 - Enable real-time updates */

/* === GLOBAL VARIABLES ===
 * 
 * keep_running: Controls the main loop in real-time mode.
 * - volatile: Tells compiler this can change unexpectedly (by signal handler)
 * - sig_atomic_t: Guarantees atomic read/write (safe in signal handlers)
 * 
 * This is the proper way to communicate between a signal handler and main code.
 */
static volatile sig_atomic_t keep_running = 1;

/* === DATA STRUCTURES ===
 * 
 * mem_stats_t: Holds memory statistics parsed from /proc/[pid]/status
 * All values are in kilobytes (KB).
 */
typedef struct {
    unsigned long vm_size;      /* Virtual memory size - total address space */
    unsigned long vm_rss;       /* Resident Set Size - RAM actually used */
    unsigned long vm_shared;    /* Shared memory (mapped files, shared libs) */
    unsigned long vm_text;      /* Text segment size (executable code) */
    unsigned long vm_data;      /* Data segment size (variables, heap) */
} mem_stats_t;

/* === FUNCTION PROTOTYPES ===
 * Declaring functions before they're defined (good C practice)
 */
static void print_usage(const char *prog_name);
static void signal_handler(int signum);
static int parse_proc_maps(pid_t pid);
static int parse_proc_status(pid_t pid, mem_stats_t *stats);
static void display_memory_stats(const mem_stats_t *stats);
static int validate_pid(pid_t pid);


/* ============================================================
 * FUNCTION: signal_handler
 * ============================================================
 * PURPOSE: 
 *   Handle SIGINT (Ctrl+C) and SIGTERM signals gracefully.
 *   Instead of abruptly terminating, we set a flag to exit cleanly.
 * 
 * PARAMETERS:
 *   signum - The signal number received (SIGINT=2, SIGTERM=15)
 * 
 * NOTES:
 *   - Signal handlers should be short and simple
 *   - Only use async-signal-safe functions (not printf!)
 *   - We just set a flag and let main() handle cleanup
 */
static void signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        keep_running = 0;  /* Signal main loop to stop */
    }
}


/* ============================================================
 * FUNCTION: print_usage
 * ============================================================
 * PURPOSE:
 *   Display help message showing all available options.
 *   Called when user passes -h/--help or invalid options.
 */
static void print_usage(const char *prog_name) {
    fprintf(stderr, "Usage: %s [OPTIONS] [PID]\n\n", prog_name);
    fprintf(stderr, "Display detailed memory usage information.\n\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -m, --maps          Show memory maps\n");
    fprintf(stderr, "  -s, --status        Show memory status\n");
    fprintf(stderr, "  -u, --summary       Show memory summary (default)\n");
    fprintf(stderr, "  -r, --realtime      Real-time monitoring mode\n");
    fprintf(stderr, "  -i, --interval N    Update interval in seconds (default: 1)\n");
    fprintf(stderr, "  -h, --help          Display this help message\n");
}


/* ============================================================
 * FUNCTION: validate_pid
 * ============================================================
 * PURPOSE:
 *   Check if a process with the given PID exists.
 *   We do this by checking if /proc/[pid]/ directory exists.
 * 
 * PARAMETERS:
 *   pid - Process ID to validate
 * 
 * RETURNS:
 *   0 on success (process exists)
 *  -1 on failure (process doesn't exist)
 * 
 * HOW IT WORKS:
 *   In Linux, every process has a directory /proc/[pid]/
 *   If this directory exists, the process is running.
 */
static int validate_pid(pid_t pid) {
    char path[256];
    
    /* Build the path: /proc/[pid] */
    snprintf(path, sizeof(path), "/proc/%d", pid);
    
    /* access() checks if path exists (F_OK = existence check) */
    if (access(path, F_OK) == -1) {
        fprintf(stderr, "Error: Process %d does not exist\n", pid);
        return -1;
    }
    return 0;
}


/* ============================================================
 * FUNCTION: parse_proc_status
 * ============================================================
 * PURPOSE:
 *   Read and parse /proc/[pid]/status to get memory statistics.
 *   This file contains various process information in "Key: Value" format.
 * 
 * PARAMETERS:
 *   pid   - Process ID to examine
 *   stats - Pointer to struct where we'll store the results
 * 
 * RETURNS:
 *   0 on success
 *  -1 on failure
 * 
 * FILE FORMAT EXAMPLE (/proc/self/status):
 *   Name:   memview
 *   VmSize:     2688 kB
 *   VmRSS:      1408 kB
 *   VmData:      224 kB
 *   ...
 * 
 * KEY CONCEPTS:
 *   - fopen/fgets: Standard C file I/O
 *   - strncmp: Compare first N characters of strings
 *   - sscanf: Parse formatted data from string
 */
static int parse_proc_status(pid_t pid, mem_stats_t *stats) {
    char filepath[256];
    
    /* Build path to status file: /proc/[pid]/status */
    snprintf(filepath, sizeof(filepath), "/proc/%d/status", pid);
    
    /* Open file for reading */
    FILE *fp = fopen(filepath, "r");
    if (!fp) {
        fprintf(stderr, "Error opening %s: %s\n", filepath, strerror(errno));
        return -1;
    }
    
    /* Initialize all stats to zero */
    memset(stats, 0, sizeof(mem_stats_t));
    
    /* Read file line by line */
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        /* 
         * Check each line for the fields we're interested in.
         * strncmp compares first N characters.
         * If match, use sscanf to extract the numeric value.
         * The " %lu" format skips whitespace then reads unsigned long.
         */
        if (strncmp(line, "VmSize:", 7) == 0) {
            sscanf(line + 7, " %lu", &stats->vm_size);
        } else if (strncmp(line, "VmRSS:", 6) == 0) {
            sscanf(line + 6, " %lu", &stats->vm_rss);
        } else if (strncmp(line, "RssFile:", 8) == 0) {
            sscanf(line + 8, " %lu", &stats->vm_shared);
        } else if (strncmp(line, "VmExe:", 6) == 0) {
            sscanf(line + 6, " %lu", &stats->vm_text);
        } else if (strncmp(line, "VmData:", 7) == 0) {
            sscanf(line + 7, " %lu", &stats->vm_data);
        }
    }
    
    /* Always close files when done! */
    fclose(fp);
    return 0;
}


/* ============================================================
 * FUNCTION: display_memory_stats
 * ============================================================
 * PURPOSE:
 *   Pretty-print the memory statistics to stdout.
 *   Shows values in both KB and MB for readability.
 */
static void display_memory_stats(const mem_stats_t *stats) {
    printf("\n=== Memory Statistics ===\n");
    printf("  Virtual Memory Size:  %10lu KB (%6.2f MB)\n", 
           stats->vm_size, stats->vm_size / 1024.0);
    printf("  Resident Set Size:    %10lu KB (%6.2f MB)\n", 
           stats->vm_rss, stats->vm_rss / 1024.0);
    printf("  Shared Memory:        %10lu KB (%6.2f MB)\n", 
           stats->vm_shared, stats->vm_shared / 1024.0);
    printf("  Text (Code) Size:     %10lu KB (%6.2f MB)\n", 
           stats->vm_text, stats->vm_text / 1024.0);
    printf("  Data + Stack Size:    %10lu KB (%6.2f MB)\n", 
           stats->vm_data, stats->vm_data / 1024.0);
}


/* ============================================================
 * FUNCTION: parse_proc_maps
 * ============================================================
 * PURPOSE:
 *   Read and display /proc/[pid]/maps which shows all memory
 *   regions (virtual memory areas) of a process.
 * 
 * FILE FORMAT (/proc/[pid]/maps):
 *   address           perms offset  dev   inode   pathname
 *   5d610cc88000-5d610cc89000 r--p 00000000 08:01 1234 /path/to/file
 * 
 * FIELDS:
 *   - address: Start-End virtual addresses
 *   - perms: r=read, w=write, x=execute, p=private/s=shared
 *   - offset: Offset in the mapped file
 *   - dev: Device (major:minor)
 *   - inode: Inode number on the device
 *   - pathname: File path (or [heap], [stack], etc.)
 * 
 * PERMISSION MEANINGS:
 *   r-xp = executable code (text segment)
 *   rw-p = read-write data (data segment, heap, stack)
 *   r--p = read-only data
 */
static int parse_proc_maps(pid_t pid) {
    char filepath[256];
    
    /* Build path: /proc/[pid]/maps */
    snprintf(filepath, sizeof(filepath), "/proc/%d/maps", pid);
    
    FILE *fp = fopen(filepath, "r");
    if (!fp) {
        fprintf(stderr, "Error opening %s: %s\n", filepath, strerror(errno));
        return -1;
    }
    
    /* Print header */
    printf("\n=== Memory Maps for Process %d ===\n", pid);
    printf("  %-18s %-18s %-5s %s\n", "Start", "End", "Perms", "Path");
    printf("  --------------------------------------------------------------\n");
    
    /* Read and parse each line */
    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        char addr_start[32], addr_end[32], perms[8], pathname[256] = "";
        unsigned long offset, dev_major, dev_minor, inode;
        
        /* Parse the line using sscanf
         * %[^-] = read until '-' character
         * %s = read string
         * %lx = read hexadecimal long
         */
        int n = sscanf(line, "%[^-]-%s %s %lx %lx:%lx %lu %[^\n]",
                       addr_start, addr_end, perms, &offset, 
                       &dev_major, &dev_minor, &inode, pathname);
        
        /* Print if we got at least the essential fields */
        if (n >= 4) {
            printf("  %-18s %-18s %s", addr_start, addr_end, perms);
            if (n >= 8 && strlen(pathname) > 0) {
                /* Skip leading whitespace in pathname */
                char *path = pathname;
                while (*path == ' ') path++;
                printf(" %s", path);
            }
            printf("\n");
        }
    }
    
    fclose(fp);
    return 0;
}


/* ============================================================
 * FUNCTION: main
 * ============================================================
 * PURPOSE:
 *   Entry point. Handles:
 *   1. Command-line argument parsing
 *   2. Signal handler setup
 *   3. Main display loop
 * 
 * KEY CONCEPTS DEMONSTRATED:
 *   - getopt_long(): Parse both short (-s) and long (--status) options
 *   - sigaction(): Modern, reliable signal handling
 *   - Bit flags: Combine multiple options with bitwise OR
 */
int main(int argc, char *argv[]) {
    /* Default to viewing our own process */
    pid_t target_pid = getpid();
    int flags = 0;          /* Bit flags for display options */
    int interval = 1;       /* Update interval for real-time mode */
    
    /* === SIGNAL HANDLING SETUP ===
     * 
     * We use sigaction() instead of signal() because:
     * - More portable across Unix systems
     * - More control over signal behavior
     * - Can specify which signals to block during handler
     */
    struct sigaction sa;
    sa.sa_handler = signal_handler;     /* Our handler function */
    sigemptyset(&sa.sa_mask);           /* Don't block other signals */
    sa.sa_flags = 0;                    /* No special flags */
    sigaction(SIGINT, &sa, NULL);       /* Handle Ctrl+C */
    sigaction(SIGTERM, &sa, NULL);      /* Handle kill command */
    
    /* === COMMAND-LINE PARSING ===
     * 
     * getopt_long() handles both:
     *   Short options: -s, -m, -h
     *   Long options: --status, --maps, --help
     * 
     * The long_options array defines available options.
     */
    static struct option long_options[] = {
        {"maps",     no_argument,       0, 'm'},
        {"status",   no_argument,       0, 's'},
        {"summary",  no_argument,       0, 'u'},
        {"realtime", no_argument,       0, 'r'},
        {"interval", required_argument, 0, 'i'},
        {"help",     no_argument,       0, 'h'},
        {0, 0, 0, 0}  /* Terminator */
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "msuri:h", long_options, NULL)) != -1) {
        switch (opt) {
            case 'm': flags |= SHOW_MAPS; break;      /* Turn on maps bit */
            case 's': flags |= SHOW_STATUS; break;    /* Turn on status bit */
            case 'u': flags |= SHOW_SUMMARY; break;   /* Turn on summary bit */
            case 'r': flags |= REALTIME_MODE; break;  /* Turn on realtime bit */
            case 'i': interval = atoi(optarg); break; /* Set interval */
            case 'h': print_usage(argv[0]); return 0;
            default: print_usage(argv[0]); return 1;
        }
    }
    
    /* If no display options specified, default to summary */
    if (!(flags & (SHOW_MAPS | SHOW_STATUS | SHOW_SUMMARY))) {
        flags |= SHOW_SUMMARY;
    }
    
    /* Check for PID argument after options */
    if (optind < argc) {
        target_pid = atoi(argv[optind]);
    }
    
    /* Validate the PID exists */
    if (validate_pid(target_pid) == -1) return 1;
    
    /* === MAIN DISPLAY LOOP ===
     * 
     * In real-time mode, this loops until Ctrl+C.
     * Otherwise, it runs once (do-while with false condition).
     */
    do {
        /* Clear screen in real-time mode (ANSI escape codes) */
        if (flags & REALTIME_MODE) printf("\033[2J\033[H");
        
        /* Print header */
        printf("Memory View - Process %d\n", target_pid);
        printf("============================================\n");
        
        /* Show memory statistics if requested */
        if (flags & (SHOW_STATUS | SHOW_SUMMARY)) {
            mem_stats_t stats;
            if (parse_proc_status(target_pid, &stats) == 0) {
                display_memory_stats(&stats);
            }
        }
        
        /* Show memory maps if requested */
        if (flags & SHOW_MAPS) {
            parse_proc_maps(target_pid);
        }
        
        /* In real-time mode, wait and repeat */
        if (flags & REALTIME_MODE) {
            printf("\n(Press Ctrl+C to exit)\n");
            sleep(interval);
        }
    } while ((flags & REALTIME_MODE) && keep_running);
    
    return 0;
}