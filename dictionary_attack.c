//code and its usage is explained in following blog : https://www.codexpace.ml/2022/03/dictionary-attacks.html
#define _XOPEN_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <string.h>

//barf a message and exit
void barf(char *msg ,char *extra){
    printf(msg ,extra);
    return;
}

//a dictionary attack
int main(int argc ,char *argv[]){
    FILE *word_list;
    char *hash ,word[30] ,salt[3];

    if(argc < 2){
        barf("[+] Usage : %s <wordlist file> <password hash>\n" ,argv[0]);
    }

    //first two bytes of the hash are salt
    strncpy(salt ,argv[2] ,2);
    //terminate string
    salt[2] = '/0';

    printf("[+] Salt value \'%s\'\n" ,salt);

    //open the wordlist
    if((word_list = fopen(argv[1] ,"r")) == NULL){
        barf("[+] Fatal: couldn't open the file \'%s\' .\n" ,argv[1]);
    }

    //read each word
    while(fgets(word ,30 ,word_list) != NULL){
        //remove the '\n' byte from an end
        word[strlen(word)-1] = '\0';
        //hash the word using salt
        hash = crypt(word ,salt);
        printf("[+] trying word: %-30s ==> %15s\n" ,word ,hash);

        //compare the hash and check if it matches
        if(strcmp(hash ,argv[2] ) == 0){
            printf("[+] The hash \"%s\" is from " ,argv[2]);
            printf("[+] plaintext password \"%s\".\n" ,word);
            fclose(word_list);
            return 0;
        }
    }

    //In case we couldn't find the plaintext password in the supplied wordlist\n
    printf("couldn't find the plaintext password\n");
    fclose(word_list);

    return 0;

}
