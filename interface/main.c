#include "main.h"

/* get an int from a file or -1 on error */
int read_int(char * path){
    int val = -1;
    FILE * fp;
    fp = fopen(path, "r");
    if (!fp){
        perror("Error opening file");
        return val;
    }
    if (fscanf(fp, "%d", &val) != 1){
        perror("Error reading file");
    }
    fclose(fp);
    return val;
}

/* write a char to a file */
void write_char(char * path, char c){
    FILE * fp;
    fp = fopen(path, "w");
    if (!fp){
        perror("Error opening file");
        return;
    }
    if (fprintf(fp, c) < 0){
        perror("Error writing file");
    }
    fclose(fp);
}

int main(int argc, char const *argv[]){
    if (argc > 2){
        printf("Invalid number of arguments.\n");
        return -1;
    }
    if (1 == argc){ // no arguments, print
        print_counts();
        return 0;
    }
    if (strcmp(argv[1], "0") == 0){ // only reset if passed argument is '0'
        reset_counts();
        return 0;
    }
    printf("Invalid argument.\n");
    return -1;
}
