#define _XOPEN_SOURCE 500
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <pwd.h>
#include <ftw.h>
#include <pthread.h>
#include <libgen.h>
#include <time.h>
#include <stdarg.h>

#define MAX_WATCHES 65536
#define EVENT_SIZE  (sizeof(struct inotify_event))
#define BUF_LEN     (1024 * (EVENT_SIZE + 16))
#define LOG_FILE_PATH "/var/log/sysmonitor.log"

// Globals
char *wd_paths[MAX_WATCHES] = {NULL};
int inotify_fd;
FILE *log_file = NULL;
pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

// --- THREAD-SAFE LOGGING FUNCTION ---
void log_event(const char *format, ...) {
    // 1. Generate Timestamp
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char time_str[24];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", t);

    // 2. Lock Mutex to prevent threads from writing over each other
    pthread_mutex_lock(&log_mutex);

    // 3. Setup variadic arguments
    va_list args;
    
    // Print to terminal
    printf("[%s] ", time_str);
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    printf("\n");

    // Print to log file
    if (log_file) {
        fprintf(log_file, "[%s] ", time_str);
        va_start(args, format);
        vfprintf(log_file, format, args);
        va_end(args);
        fprintf(log_file, "\n");
        fflush(log_file); // Force write to disk immediately
    }

    // 4. Unlock Mutex
    pthread_mutex_unlock(&log_mutex);
}

// --- INOTIFY CALLBACK ---
int add_watch(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
    if (typeflag == FTW_D) {
        if (strstr(fpath, "/.cache") || strstr(fpath, "/.git")) {
            return 0; 
        }
        
        int wd = inotify_add_watch(inotify_fd, fpath, IN_MODIFY | IN_CREATE | IN_DELETE | IN_MOVE);
        if (wd >= 0 && wd < MAX_WATCHES) {
            wd_paths[wd] = strdup(fpath); 
        }
    }
    return 0;
}

// --- FILE MONITOR THREAD ---
void *monitor_files(void *arg) {
    char buffer[BUF_LEN];
    
    inotify_fd = inotify_init();
    if (inotify_fd < 0) {
        perror("inotify_init");
        return NULL;
    }

    nftw("/etc", add_watch, 20, FTW_PHYS);
    
    const char *sudo_user = getenv("SUDO_USER");
    if (sudo_user) {
        struct passwd *pw = getpwnam(sudo_user);
        if (pw) {
            char conf_path[512];
            snprintf(conf_path, sizeof(conf_path), "%s/.config", pw->pw_dir);
            nftw(conf_path, add_watch, 20, FTW_PHYS);
        }
    }

    log_event("[INFO] Native C inotify listener active.");

    while (1) {
        int length = read(inotify_fd, buffer, BUF_LEN);
        if (length < 0) break;

        int i = 0;
        while (i < length) {
            struct inotify_event *event = (struct inotify_event *) &buffer[i];
            if (event->len) {
                if (!strstr(event->name, ".swp") && !strstr(event->name, "~")) {
                    const char *dir_path = wd_paths[event->wd] ? wd_paths[event->wd] : "unknown_dir";
                    log_event("[FILE] %s/%s", dir_path, event->name);
                }
            }
            i += EVENT_SIZE + event->len;
        }
    }
    return NULL;
}

// --- COMMAND MONITOR THREAD ---
void monitor_commands() {
    const char *bpf_prog = 
        "tracepoint:syscalls:sys_enter_execve { printf(\"EXEC|%d|%s\\n\", uid, str(args->filename)); } "
        "tracepoint:syscalls:sys_enter_chdir { printf(\"CD|%d|%s\\n\", uid, str(args->filename)); }";
    
    char cmd[2048];
    snprintf(cmd, sizeof(cmd), "bpftrace -e '%s'", bpf_prog);
    
    FILE *fp = popen(cmd, "r");
    if (!fp) {
        perror("popen");
        exit(EXIT_FAILURE);
    }

    log_event("[INFO] Kernel eBPF probe injected. Monitoring executions...");

    char line[1024];
    while (fgets(line, sizeof(line), fp) != NULL) {
        line[strcspn(line, "\n")] = 0; 

        if (strncmp(line, "EXEC|", 5) == 0 || strncmp(line, "CD|", 3) == 0) {
            char *type_token = strtok(line, "|");
            char *uid_token  = strtok(NULL, "|");
            char *path_token = strtok(NULL, "|");

            if (type_token && uid_token && path_token) {
                int uid = atoi(uid_token);
                struct passwd *pw = getpwuid(uid);
                const char *username = pw ? pw->pw_name : uid_token;
                
                if (strcmp(type_token, "CD") == 0) {
                    log_event("[DIR]  User: %-10s | Changed directory to: %s", username, path_token);
                } else {
                    char *binary_name = basename(path_token);
                    if (strcmp(binary_name, "bpftrace") != 0 && strcmp(binary_name, "sh") != 0) {
                        log_event("[EXEC] User: %-10s | Command: %s", username, binary_name);
                    }
                }
            }
        }
    }
    pclose(fp);
}

// --- MAIN ENTRY ---
int main() {
    if (geteuid() != 0) {
        fprintf(stderr, "ERROR: Monitoring kernel syscalls requires root.\n");
        fprintf(stderr, "Please run with: sudo ./sysmonitor\n");
        return EXIT_FAILURE;
    }

    // Open log file in Append mode
    log_file = fopen(LOG_FILE_PATH, "a");
    if (!log_file) {
        perror("Failed to open log file");
        // We don't exit here; we can still run and print to the terminal if the file fails
    }

    log_event("=== SYSTEM MONITOR STARTED ===");

    pthread_t file_thread;
    if (pthread_create(&file_thread, NULL, monitor_files, NULL) != 0) {
        perror("pthread_create");
        return EXIT_FAILURE;
    }

    monitor_commands();

    if (log_file) fclose(log_file);
    return EXIT_SUCCESS;
}