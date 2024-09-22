#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

static const int FILE_SIZE = 17 * 1024;
static const char *FILENAME = "17K.txt";

int main() {
	
	int fd;
	char *buffer = NULL;

	buffer = (char *)malloc(FILE_SIZE);
	if (buffer == NULL) {
		printf("Memory allocation failed\n");
		exit(1);
	}

	memset(buffer, 0, FILE_SIZE);
	for (int i = 0; i < FILE_SIZE; i++) {
		if (i < (16 * 1024)) {
			buffer[i] = 'A';
		} else {
			buffer[i] = 'B';
		}
	}

	fd = open(FILENAME, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		perror("Failed to open file");
		free(buffer);
		exit(1);
	}

	ssize_t written = write(fd, buffer, FILE_SIZE);
	if (written != FILE_SIZE) {
		perror("Failed to write data to file");
		free(buffer);
		exit(1);
	}

	if (close(fd) < 0) {
		perror("Failed to close file");
		free(buffer);
		exit(1);
	}

	free(buffer);
	printf("Successfully written %d bytes to %s \n", FILE_SIZE, FILENAME);

	return 0;
}
