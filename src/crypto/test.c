#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>

unsigned char *id_create() {

        unsigned char *id = calloc(128 , sizeof(id));
        int fd = open("/dev/urandom" , O_RDONLY);

        ssize_t r = read(fd , id , 128);

        if(r <= 0 ) {
                return NULL;
        }else {
                close(fd);
        }
                return id;
}

int main() {

	unsigned char *id;

	id = id_create();

	for(int i = 0; i <= 127 ; i++) {
		printf("%x " ,id[i]);
	}
	printf("\n");
}
