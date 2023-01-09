#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

// Function to check if a system call is a network-related syscall
int is_net_syscall(const char* syscall_name) {
    return strncmp(syscall_name, "recv", 4) == 0 ||
           strncmp(syscall_name, "send", 4) == 0 ||
           strncmp(syscall_name, "connect", 7) == 0 ||
           strncmp(syscall_name, "accept", 6) == 0 ||
           strncmp(syscall_name, "bind", 4) == 0 ||
           strncmp(syscall_name, "listen", 6) == 0;
}

// Function to check if a system call has an error return value
int has_error(long syscall_result) {
    return syscall_result < 0;
}

// Function to print the input arguments of a system call with an error return value
void print_error_syscall(const char* syscall_name, long syscall_parameters[], int num_parameters) {
    long err = -syscall_result;
    printf("System call: %s\n", syscall_name);
    printf("Error: %s\n", strerror(err));
    printf("Arguments: ");
    for (int i = 0; i < num_parameters; i++) {
        printf("%ld ", syscall_parameters[i]);
    }
    printf("\n");
}

// Function to log error messages to a file
void log_error(const char* syscall_name, long syscall_parameters[], int num_parameters, FILE* log_file) {
    long err = -syscall_result;
    fprintf(log_file, "System call: %s\nError: %s\nArguments: ", syscall_name, strerror(err));
    for (int i = 0; i < num_parameters; i++) {
        fprintf(log_file, "%ld ", syscall_parameters[i]);
    }
    fprintf(log_file, "\n");
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Error: missing PID argument\n");
        return 1;
    }

    // Convert the PID argument to an integer
    pid_t pid = atoi(argv[1]);

    // Attach to the process
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
        fprintf(stderr, "Error attaching to process: %s\n", strerror(errno));
        return 1;
    }

    // Wait for the process to stop
    int wait_status;
    waitpid(pid, &wait_status);
    // Open a log file for writing
FILE* log_file = fopen("error.log", "w");

// Set a breakpoint at the entry of each system call
ptrace(PTRACE_SYSCALL, pid, NULL, NULL);

// Start the debugger
int wait_status;
while (1) {
    // Wait for the next system call
    ptrace(PTRACE_CONT, pid, NULL, NULL);
    waitpid(pid, &wait_status, 0);

    // Check if the process has exited
    if (WIFEXITED(wait_status)) {
        break;
    }

    // Get the system call number and name
    long syscall_number = ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * ORIG_RAX);
    const char* syscall_name = get_syscall_name(syscall_number);

    // Use gdb to get the system call parameters
    char command[128];
    snprintf(command, 128, "gdb --batch --pid %d -ex 'info registers'", pid);
    FILE* gdb_output = popen(command, "r");
    if (gdb_output == NULL) {
        fprintf(stderr, "Error getting system call parameters: %s\n", strerror(errno));
        return 1;
    }
    long syscall_parameters[6];
    int num_parameters = 0;
    char line[128];
    while (fgets(line, 128, gdb_output)) {
        if (strncmp(line, " rdi ", 5) == 0 ||
            strncmp(line, " rsi ", 5) == 0 ||
            strncmp(line, " rdx ", 5) == 0 ||
            strncmp(line, " r10 ", 5) == 0 ||
            strncmp(line, " r8 ", 4) == 0 ||
            strncmp(line, " r9 ", 4) == 0) {
            syscall_parameters[num_parameters] = strtol(line + 5, NULL, 16);
            num_parameters++;
        }
    }
    pclose(gdb_output);

    // Set a breakpoint at the exit of the system call
    ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
    waitpid(pid, &wait_status, 0);

    // Get the system call result
    long syscall_result = ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * RAX);

    // If the system call is a network-related syscall with an error return value, print the input arguments and log the error
    if (is_net_syscall(syscall_name) && has_error(syscall_result)) {
        print_error_syscall(syscall_name, syscall_parameters, num_parameters);
        log_error(syscall_name, syscall_parameters, num_parameters, log_file);
    }
}

        // Close the log file
        fclose(log_file);

        // Detach from the process
        ptrace(PTRACE_DETACH, pid, NULL, NULL);

        return 0;
}
