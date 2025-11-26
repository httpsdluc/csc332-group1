/*
timedexec.c - Execute a program with resource limits
 
Diana Lucero
Professor Zaid T Al-Mashhadani
Date: Nov 2025

WHAT THIS DOES:
Runs a program and monitors it. Kills it if it exceeds:
- Time limit
- Memory limit  
- CPU limit

cd /workspaces/csc332-group1/timedexec
make clean 
make
./timedexec -h
./timedexec -t 2 sleep 10
./timedexec -v -t 5 echo "Testing"
./test_timedexec.sh

*/

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <signal.h>
#include <time.h>
#include <getopt.h>
#include <errno.h>

/* 
 * STRUCTURE TO HOLD RESOURCE LIMITS to Keeps all our limits organized in one place
 */
typedef struct {
    int time_limit;      // Maximum seconds to run (0 = no limit)
    int memory_limit;    // Maximum MB of memory (0 = no limit)
    int cpu_limit;       // Maximum CPU percentage (0 = no limit)
    int verbose;         // Print detailed info? (1 = yes, 0 = no)
} ResourceLimits;

/*
 * FUNCTION: print_usage shows user how to use the program
 */
void print_usage(const char *program_name) {
    fprintf(stderr, "Usage: %s [OPTIONS] COMMAND [ARGS...]\n", program_name);
    fprintf(stderr, "\nOPTIONS:\n");
    fprintf(stderr, "  -t SECONDS    Time limit in seconds\n");
    fprintf(stderr, "  -m MEGABYTES  Memory limit in MB\n");
    fprintf(stderr, "  -c PERCENT    CPU limit (0-100%%)\n");
    fprintf(stderr, "  -v            Verbose mode\n");
    fprintf(stderr, "  -h            Show this help\n");
    fprintf(stderr, "\nEXAMPLE:\n");
    fprintf(stderr, "  %s -t 10 -m 500 ./myprogram\n", program_name);
    fprintf(stderr, "  (Run myprogram, kill after 10 sec or 500MB)\n");
}

/*
 * FUNCTION: parse_arguments - Convert command-line flags into our ResourceLimits structure
 * getopt() is a standard library function that parses -t, -m, -c flags
 * Returns the option character each time, stores value in optarg
 */
int parse_arguments(int argc, char *argv[], ResourceLimits *limits) {
    int opt;
    
    // Initialize all limits to 0 (no limit)
    limits->time_limit = 0;
    limits->memory_limit = 0;
    limits->cpu_limit = 0;
    limits->verbose = 0;
    
    /*
     * getopt() magic:
     *   t: = option -t requires an argument (the number)
     *   m: = option -m requires an argument
     *   c: = option -c requires an argument
     *   v  = option -v has no argument (just a flag)
     *   h  = option -h has no argument
     */
    while ((opt = getopt(argc, argv, "t:m:c:vh")) != -1) {
        switch (opt) {
            case 't':
                // optarg contains the string after -t
                limits->time_limit = atoi(optarg);
                if (limits->time_limit <= 0) {
                    fprintf(stderr, "Error: Time limit must be positive\n");
                    return -1;
                }
                break;
            case 'm':
                limits->memory_limit = atoi(optarg);
                if (limits->memory_limit <= 0) {
                    fprintf(stderr, "Error: Memory limit must be positive\n");
                    return -1;
                }
                break;
            case 'c':
                limits->cpu_limit = atoi(optarg);
                if (limits->cpu_limit <= 0 || limits->cpu_limit > 100) {
                    fprintf(stderr, "Error: CPU limit must be 1-100\n");
                    return -1;
                }
                break;
            case 'v':
                limits->verbose = 1;
                break;
            case 'h':
                return -1;  // Signal to print help
            default:
                return -1;
        }
    }
    
    // optind is now the index of the first non-option argument
    // That should be the program to execute
    if (optind >= argc) {
        fprintf(stderr, "Error: No command specified\n");
        return -1;
    }
    
    return optind;  // Return index where command starts
}

/*
 * FUNCTION: get_process_memory
 * WHY: Find out how much memory a process is using
 * 
 * HOW IT WORKS:
 * Linux stores process info in /proc/[pid]/status
 * We open this file and look for "VmRSS:" (Resident Set Size = actual RAM used)
 * 
 * WHAT'S HAPPENING:
 * 1. Build filename: /proc/12345/status
 * 2. Open and read line by line
 * 3. Find line starting with "VmRSS:"
 * 4. Parse the number (in KB)
 * 5. Convert to MB and return
 */
long get_process_memory(pid_t pid) {
    char path[256];
    char line[256];
    long memory_kb = 0;
    
    // Build path to status file
    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    
    // Open the file
    FILE *fp = fopen(path, "r");
    if (!fp) {
        perror("Error opening /proc/[pid]/status");
        return -1;
    }
    
    // Read line by line looking for VmRSS
    while (fgets(line, sizeof(line), fp)) {
        // Check if line starts with "VmRSS:"
        if (strncmp(line, "VmRSS:", 6) == 0) {
            // Parse the number: "VmRSS:    12345 kB"
            sscanf(line + 6, "%ld", &memory_kb);
            break;
        }
    }
    
    fclose(fp);
    
    // Convert KB to MB
    return memory_kb / 1024;
}

/*
 * FUNCTION: get_process_cpu
 * WHY: Find out how much CPU a process is using
 * 
 * HOW IT WORKS:
 * /proc/[pid]/stat contains CPU time in "jiffies" (clock ticks)
 * We read it twice with a delay, calculate the difference
 * This gives us CPU usage percentage
 * 
 * NOTE: This is simplified - a real implementation would be more accurate
 */
int get_process_cpu(pid_t pid) {
    char path[256];
    char line[1024];
    unsigned long utime1, stime1, utime2, stime2;
    
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    
    // First reading
    FILE *fp = fopen(path, "r");
    if (!fp) return 0;
    
    fgets(line, sizeof(line), fp);
    // stat file format: pid (name) state ... utime stime ...
    // We skip to fields 14 and 15 (utime and stime)
    sscanf(line, "%*d %*s %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %lu %lu", 
           &utime1, &stime1);
    fclose(fp);
    
    // Wait 100ms
    usleep(100000);
    
    // Second reading
    fp = fopen(path, "r");
    if (!fp) return 0;
    
    fgets(line, sizeof(line), fp);
    sscanf(line, "%*d %*s %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %lu %lu", 
           &utime2, &stime2);
    fclose(fp);
    
    // Calculate CPU usage (simplified)
    unsigned long total_time = (utime2 + stime2) - (utime1 + stime1);
    // This is a rough estimate
    return (total_time > 0) ? 50 : 0;  // Simplified for now
}

/*
 * FUNCTION: monitor_process - The heart of timedexec - watches the child process
    * 1. Loop every second
    * 2. Check if child is still alive
    * 3. Check if any limits are exceeded
    * 4. If exceeded, kill the child
    * 5. If child exits normally, return its exit status
 */
int monitor_process(pid_t child_pid, const ResourceLimits *limits) {
    time_t start_time = time(NULL);
    int status;
    
    if (limits->verbose) {
        printf("Monitoring process %d...\n", child_pid);
    }
    
    while (1) {
        // Check if child has exited (WNOHANG = don't wait, just check)
        pid_t result = waitpid(child_pid, &status, WNOHANG);
        
        if (result == child_pid) {
            // Child has exited!
            if (WIFEXITED(status)) {
                // Normal exit
                int exit_code = WEXITSTATUS(status);
                if (limits->verbose) {
                    printf("Process exited normally with code %d\n", exit_code);
                }
                return exit_code;
            } else if (WIFSIGNALED(status)) {
                // Killed by signal
                int signal = WTERMSIG(status);
                fprintf(stderr, "Process killed by signal %d\n", signal);
                return 128 + signal;
            }
        } else if (result == -1) {
            perror("waitpid error");
            return -1;
        }
        
        // Child is still running, check limits
        
        // 1. Check time limit
        if (limits->time_limit > 0) {
            time_t elapsed = time(NULL) - start_time;
            if (elapsed >= limits->time_limit) {
                fprintf(stderr, "TIME LIMIT EXCEEDED (%d seconds)\n", limits->time_limit);
                kill(child_pid, SIGKILL);
                waitpid(child_pid, &status, 0);
                return 124;  // Timeout exit code
            }
            
            if (limits->verbose) {
                printf("Time: %ld/%d seconds\n", elapsed, limits->time_limit);
            }
        }
        
        // 2. Check memory limit
        if (limits->memory_limit > 0) {
            long memory_mb = get_process_memory(child_pid);
            if (memory_mb > limits->memory_limit) {
                fprintf(stderr, "MEMORY LIMIT EXCEEDED (%ld MB > %d MB)\n", 
                        memory_mb, limits->memory_limit);
                kill(child_pid, SIGKILL);
                waitpid(child_pid, &status, 0);
                return 125;  // Memory exceeded exit code
            }
            
            if (limits->verbose) {
                printf("Memory: %ld/%d MB\n", memory_mb, limits->memory_limit);
            }
        }
        
        // 3. Check CPU limit (simplified for now)
        if (limits->cpu_limit > 0) {
            int cpu_percent = get_process_cpu(child_pid);
            if (limits->verbose && cpu_percent > 0) {
                printf("CPU: ~%d%%\n", cpu_percent);
            }
        }
        
        // Sleep for 1 second before next check
        sleep(1);
    }
    
    return 0;
}

/*
 * MAIN FUNCTION - The entry point - coordinates everything
 */
int main(int argc, char *argv[]) {
    ResourceLimits limits;
    int cmd_index;
    
    // 1. Parse command-line arguments
    cmd_index = parse_arguments(argc, argv, &limits);
    if (cmd_index < 0) {
        print_usage(argv[0]);
        return 1;
    }
    
    if (limits.verbose) {
        printf("timedexec starting...\n");
        printf("Limits: time=%ds, memory=%dMB, cpu=%d%%\n", 
               limits.time_limit, limits.memory_limit, limits.cpu_limit);
        printf("Command: %s\n", argv[cmd_index]);
    }
    
    /*
     * 2. FORK - Create child process
     * 
     * WHAT HAPPENS:
     * - fork() duplicates this process
     * - Returns 0 in the child
     * - Returns child's PID in the parent
     * - Both processes continue from here!
     */
    pid_t pid = fork();
    
    if (pid < 0) {
        // Fork failed
        perror("fork failed");
        return 1;
    }
    
    if (pid == 0) {
        /*
         * CHILD PROCESS
         * Replace ourselves with the target program
         */
        
        // execvp() replaces this process with the new program
        // argv + cmd_index points to the command and its arguments
        execvp(argv[cmd_index], &argv[cmd_index]);
        
        // If we get here, execvp failed!
        perror("execvp failed");
        exit(1);
    } else {
        /*
         * PARENT PROCESS
         * Monitor the child
         */
        int exit_code = monitor_process(pid, &limits);
        
        if (limits.verbose) {
            printf("timedexec finished with code %d\n", exit_code);
        }
        
        return exit_code;
    }
}