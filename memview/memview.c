/*
 * memview.c - Displays detailed memory usage of a process or system
 * 
 * This program reads from the Linux /proc filesystem to show memory info.
 * It can display memory statistics, memory maps, and supports real-time monitoring.
 * 
 * Author: Arsenii Chan
 * Course: CSC 332
 * Date: November 25 2025
 */

#include <stdio.h>      // printf, fopen, fgets, etc.
#include <stdlib.h>     // exit, atoi
#include <string.h>     // strncmp, memset, strlen
#include <unistd.h>     // getpid, access, sleep
#include <sys/stat.h>   // file status
#include <fcntl.h>      // file control
#include <errno.h>      // errno and strerror for error messages
#include <getopt.h>     // getopt_long for command-line parsing
#include <signal.h>     // sigaction for signal handling

// Bit flags for tracking which display options are enabled
#define SHOW_MAPS       (1 << 0)
#define SHOW_STATUS     (1 << 1)
#define SHOW_SUMMARY    (1 << 2)
#define REALTIME_MODE   (1 << 4)

// Global flag for signal handler - needs to be volatile so compiler doesn't optimize it out
static volatile sig_atomic_t keep_running = 1;

// Struct to hold memory stats we parse from /proc/[pid]/status
typedef struct {
    unsigned long vm_size;      // total virtual memory
    unsigned long vm_rss;       // resident set size (actual RAM used)
    unsigned long vm_shared;    // shared memory
    unsigned long vm_text;      // code size
    unsigned long vm_data;      // data + stack size
} mem_stats_t;

// Function prototypes
static void print_usage(const char *prog_name);
static void signal_handler(int signum);
static int parse_proc_maps(pid_t pid);
static int parse_proc_status(pid_t pid, mem_stats_t *stats);
static void display_memory_stats(const mem_stats_t *stats);
static int validate_pid(pid_t pid);


// Signal handler - just sets the flag to stop the loop
// We don't do anything fancy here because signal handlers should be simple
static void signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        keep_running = 0;
    }
}


// Prints help message
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


// Check if a process exists by seeing if /proc/[pid] exists
static int validate_pid(pid_t pid) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d", pid);
    
    if (access(path, F_OK) == -1) {
        fprintf(stderr, "Error: Process %d does not exist\n", pid);
        return -1;
    }
    return 0;
}


// Parse /proc/[pid]/status to get memory statistics
// The file has lines like "VmSize:    2688 kB" that we need to parse
static int parse_proc_status(pid_t pid, mem_stats_t *stats) {
    char filepath[256];
    snprintf(filepath, sizeof(filepath), "/proc/%d/status", pid);
    
    FILE *fp = fopen(filepath, "r");
    if (!fp) {
        fprintf(stderr, "Error opening %s: %s\n", filepath, strerror(errno));
        return -1;
    }
    
    // Zero out the struct first
    memset(stats, 0, sizeof(mem_stats_t));
    
    // Read line by line and look for the fields we care about
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        // Check what field this line is and extract the value
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
    
    fclose(fp);
    return 0;
}


// Print out the memory stats in a nice format
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


// Parse /proc/[pid]/maps to show all memory regions
// Each line shows: address range, permissions, and what's mapped there
static int parse_proc_maps(pid_t pid) {
    char filepath[256];
    snprintf(filepath, sizeof(filepath), "/proc/%d/maps", pid);
    
    FILE *fp = fopen(filepath, "r");
    if (!fp) {
        fprintf(stderr, "Error opening %s: %s\n", filepath, strerror(errno));
        return -1;
    }
    
    printf("\n=== Memory Maps for Process %d ===\n", pid);
    printf("  %-18s %-18s %-5s %s\n", "Start", "End", "Perms", "Path");
    printf("  --------------------------------------------------------------\n");
    
    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        char addr_start[32], addr_end[32], perms[8], pathname[256] = "";
        unsigned long offset, dev_major, dev_minor, inode;
        
        // Parse the line - format is: start-end perms offset dev inode pathname
        int n = sscanf(line, "%[^-]-%s %s %lx %lx:%lx %lu %[^\n]",
                       addr_start, addr_end, perms, &offset, 
                       &dev_major, &dev_minor, &inode, pathname);
        
        if (n >= 4) {
            printf("  %-18s %-18s %s", addr_start, addr_end, perms);
            if (n >= 8 && strlen(pathname) > 0) {
                // Skip leading whitespace in pathname
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


int main(int argc, char *argv[]) {
    pid_t target_pid = getpid();  // default to our own process
    int flags = 0;
    int interval = 1;
    
    // Set up signal handling with sigaction (better than signal())
    struct sigaction sa;
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);   // catch Ctrl+C
    sigaction(SIGTERM, &sa, NULL);  // catch kill
    
    // Define our command-line options
    static struct option long_options[] = {
        {"maps",     no_argument,       0, 'm'},
        {"status",   no_argument,       0, 's'},
        {"summary",  no_argument,       0, 'u'},
        {"realtime", no_argument,       0, 'r'},
        {"interval", required_argument, 0, 'i'},
        {"help",     no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };
    
    // Parse command-line options
    int opt;
    while ((opt = getopt_long(argc, argv, "msuri:h", long_options, NULL)) != -1) {
        switch (opt) {
            case 'm': flags |= SHOW_MAPS; break;
            case 's': flags |= SHOW_STATUS; break;
            case 'u': flags |= SHOW_SUMMARY; break;
            case 'r': flags |= REALTIME_MODE; break;
            case 'i': interval = atoi(optarg); break;
            case 'h': print_usage(argv[0]); return 0;
            default: print_usage(argv[0]); return 1;
        }
    }
    
    // Default to summary if nothing specified
    if (!(flags & (SHOW_MAPS | SHOW_STATUS | SHOW_SUMMARY))) {
        flags |= SHOW_SUMMARY;
    }
    
    // Check if user specified a PID
    if (optind < argc) {
        target_pid = atoi(argv[optind]);
    }
    
    // Make sure the process exists
    if (validate_pid(target_pid) == -1) return 1;
    
    // Main loop - runs once normally, or keeps going in realtime mode
    do {
        // Clear screen in realtime mode
        if (flags & REALTIME_MODE) printf("\033[2J\033[H");
        
        printf("Memory View - Process %d\n", target_pid);
        printf("============================================\n");
        
        // Show stats if requested
        if (flags & (SHOW_STATUS | SHOW_SUMMARY)) {
            mem_stats_t stats;
            if (parse_proc_status(target_pid, &stats) == 0) {
                display_memory_stats(&stats);
            }
        }
        
        // Show maps if requested
        if (flags & SHOW_MAPS) {
            parse_proc_maps(target_pid);
        }
        
        // In realtime mode, wait and loop again
        if (flags & REALTIME_MODE) {
            printf("\n(Press Ctrl+C to exit)\n");
            sleep(interval);
        }
    } while ((flags & REALTIME_MODE) && keep_running);
    
    return 0;
}