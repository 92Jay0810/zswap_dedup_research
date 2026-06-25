#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <time.h>

#define PAGE_SIZE 4096

static size_t parse_size(const char *s){
	char *end;
	double value = strtod(s, &end);

	if (value <= 0) {
		fprintf(stderr, "Invalid size: %s\n", s);
		exit(1);
	}

	if(*end == 'G' || *end == 'g'){
		return (size_t)(value * 1024 * 1024 * 1024);
	} else if (*end == 'M' || *end == 'm'){
		return (size_t)(value * 1024 * 1024);
	} else if (*end == 'K' || *end == 'k'){
		return (size_t)(value * 1024);
	} else if (*end == '\0'){
		return (size_t)value;
	} else {
		fprintf(stderr, "Unknown size unit: %s\n", end);
		exit(1);
	}
}

static void fill_random_page(uint8_t *page){
	FILE *urandom = fopen("/dev/urandom","rb");
	if(!urandom){
		perror("fopen /dev/urandom");
		exit(1);
	}

	if(fread(page, 1, PAGE_SIZE, urandom) != PAGE_SIZE){
		perror("fread /dev/urandom");
		fclose(urandom);
		exit(1);
	}

	fclose(urandom);
}

int main(int argc, char **argv){
	if(argc < 2){
		fprintf(stderr,
			"Usage: %s <size> [seconds]\n"
			"Example:\n"
			"  %s 1500M 300\n"
			"  %s 2G  120\n",
			argv[0], argv[0], argv[0]);
		return 1;
	}

	size_t size = parse_size(argv[1]);
	int seconds = 0;

	if (argc >= 3){
		seconds = atoi(argv[2]);

		if(seconds < 0){
			fprintf(stderr, "Error: seconds must be >= 0\n");
			exit(EXIT_FAILURE);
		}
	}

	size_t pages = size / PAGE_SIZE;

	printf("Allocating %zu bytes (%zu MB, %zu pages)\n",
		size, size / 1024 / 1024 , pages);

	uint8_t *buf = mmap(NULL, size,
			PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS,
			-1, 0);
	if (buf == MAP_FAILED){
		perror("mmap");
		return 1;
	}

	printf("Filling memory with random page content...\n");

	for(size_t i = 0; i < pages; i++){
		fill_random_page(buf + i * PAGE_SIZE);
	}

	printf("Memory pressure active.\n");

	time_t start = time(NULL);
	volatile uint64_t checksum = 0;

	while(1){
		printf("still running... (%ld sec)\n", time(NULL)-start);
		fflush(stdout);

		if (seconds > 0 && time(NULL) - start >= seconds){
			break;
		}

		sleep(5);
	}

	munmap(buf, size);
	return 0;
}
