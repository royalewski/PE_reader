#include <stdio.h>


int main (int argc, char *argv[]){
    if(argc == 1){
	printf("No input .exe file name\n");
	return(-1);
    }
    else if(argc > 2){
	printf("Too many arguments/n");
	return(-1);
    }
    
    unsigned char buffer[64];
    FILE *f = fopen(argv[1], "rb");
    fread(buffer, 1, 64, f);

    if(buffer[0] == 'M' && buffer[1] == 'Z'){
	printf("PE indeed\n");
	for(int i = 0; i < sizeof(buffer); i++){
	    printf("%x", buffer[i]);
	}
	printf("\n");
    }

}
