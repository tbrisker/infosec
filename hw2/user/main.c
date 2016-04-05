#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <string.h>

#define PATH(file) "/sys/class/FW_interface/stats/" #file


int get_count(char * path){
    int count;
    FILE * fp;
    fp = fopen(path, "r");
    if (!fp){
        perror("Error opening file");
        return -1;
    }
    if (fscanf(fp, "%d", &count) != 1){
        perror("Error reading file");
        count = -1;
    }
    fclose(fp);
    return count;
}

void print_counts(void){
    int count = 0;
    printf("Firewall Packets Summary:\n");
    if ((count = get_count(PATH(passed)))>=0)
        printf("Number of accepted packets: %d\n", count);
    if ((count = get_count(PATH(blocked)))>=0)
        printf("Number of dropped packets: %d\n", count);
    if ((count = get_count(PATH(total)))>=0)
        printf("Total number of packets: %d\n", count);
}

void reset_counts(void){
    FILE * fp;
    fp = fopen(PATH(reset), "w");
    if (!fp){
        perror("Error opening file");
        return;
    }
    if (fprintf(fp, "%d", 0) < 0){
        perror("Error writing file");
    }
    fclose(fp);
    return;
}


int main(int argc, char const *argv[]){
    if (argc>2){
        printf("Invalid number of arguments.\n");
        return -1;
    }

    if (1==argc){
        print_counts();
    }
    else if (strcmp(argv[1], "0") == 0){
        reset_counts();
    }
    else {
        printf("Invalid argument.\n");
        return -1;
    }
    return 0;
}
