#define _GNU_SOURCE
#include <time.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

#include <sys/wait.h>
#include <sys/types.h>
#include <sys/sendfile.h>

const int total_crash_bin_count = 10000;

int get_crash_bin_number(int *solved_bin_numbers)
{
  int bin_number;
  while (1)
  {
    bin_number = rand() % total_crash_bin_count;
    for (int index = 0;; ++index)
    {
      if (solved_bin_numbers[index] == 0)
      {
        return bin_number;
      }
      else if (solved_bin_numbers[index] == bin_number)
      {
        break;
      }
    }
  }
}

void check_presence_of_crash_program(const char *program_path)
{
  char crash_program_path[50];
  for (int index = 0; index < total_crash_bin_count; ++index)
  {
    sprintf(crash_program_path, "%s-%d", program_path, index);
    if (access(crash_program_path, F_OK))
    {
      puts("[!] Challenge Under Maintenance!! Please Try Later.");
      exit(0);
    }
  }
}

int main(int argc, const char **argv, const char **envp)
{
  srand(time(NULL));

  // Runs 50 binaries and expects them to crash (raise a signal).
  const unsigned int expected_crashes = 50;
  const char *crash_program_suffix = "/opt/babyauto-crackmes/level3/crash8";

  check_presence_of_crash_program(crash_program_suffix);

  pid_t pid;
  unsigned int crashes_left;
  int solved_numbers[expected_crashes];
  char path_to_crash_program[50], path_to_input_file[20];
  int stat_loc, crash_bin_number, program_input_file_fd, flag_fd, loop_again;

  crashes_left = expected_crashes;
  memset(solved_numbers, 0, sizeof(solved_numbers));
  memset(path_to_crash_program, 0, sizeof(path_to_crash_program));
  memset(path_to_input_file, 0, sizeof(path_to_input_file));

  printf("[-] Welcome to %s!\n", *argv);
  puts("[-] This challenge series will teach you how to search for bugs in software");
  puts("[-] on a large scale. The challenge has a list of binaries for you to find");
  puts("[-] crash bugs in. You will need to find crashes in them, create a file with");
  puts("[-] the crashing input, instruct this challenge to execute the binaries with");
  puts("[-] the crashing input. Good luck!");
  puts("[+] We suggest using strings or pwntools to find the bugs!");
  puts("[-] Each program will be executed as follows:");
  printf("# /path/to/program /path/to/program_input_file\n");

  while (crashes_left)
  {
    crash_bin_number = get_crash_bin_number(solved_numbers);
    loop_again = 1;
    sprintf(path_to_crash_program, "%s-%d", crash_program_suffix, crash_bin_number);
    while (loop_again)
    {
      printf("- You must crash %d more programs to get the flag.\n", crashes_left);
      printf("Path to program: %s\n", path_to_crash_program);
      printf("Please provide path to crashing input file: ");
      fgets(path_to_input_file, 20, stdin);
      path_to_input_file[strcspn(path_to_input_file, "\n")] = 0;
      if (strstr(path_to_input_file, "flag"))
      {
        puts("[!] INVALID INPUT FILENAME! Please don't use flag in input file name.");
      }
      else
      {
        program_input_file_fd = open(path_to_input_file, O_RDONLY | O_NOFOLLOW);
        if (program_input_file_fd >= 0)
        {
          printf("[+] Running %s with input %s as UID 1337.\n", path_to_crash_program, path_to_input_file);
          pid = fork();
          if (!pid)
          {
            setgid(0x539u);
            setresuid(0x539u, 0x539u, 0x539u);
            dup2(program_input_file_fd, 0);
            close(program_input_file_fd);
            execve(path_to_crash_program, NULL, NULL);
          }
          waitpid(pid, &stat_loc, 0);
          close(program_input_file_fd);
          if ((char)((stat_loc & 0x7F) + 1) >> 1 > 0)
          {
            printf("[*] PWNED! Program terminated with signal %d.\n", stat_loc & 0x7F);
            solved_numbers[expected_crashes - crashes_left] = crash_bin_number;
            --crashes_left;
            loop_again = 0;
          }
        }
        else
        {
          puts("[!] UNABLE TO OPEN CRASHING INPUT FILE.");
        }
      }
    }
  }
  puts("[*] Congratulations! You have pwned your way to the flag!");
  flag_fd = open("/flag", 0);
  if (flag_fd == -1)
  {
    printf("[!] Issue with opening flag file!! Please Try again later.\n");
    exit(-1);
  }
  sendfile(STDOUT_FILENO, flag_fd, 0, 0x64);
  return 0;
}