// Using Modular 
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

int main(){
    FILE *fp = fopen("dictionary.txt","w");
    uint16_t temp;
    for(uint16_t state=0; ; state++){
        temp = state;
        for(int round = 0LL; round < (34567890&0xffff); round++){
            temp = 21727 * (18199 * ((25561 * (31663 * (0xF99D * (temp ^ 0x6BB1) - 16196) + 14122)) ^ 0x448C) - 11258);
        }
        printf("%d : %#x\n", state, temp&0xffff);
        fprintf(fp, "%#x\n", temp&0xffff);
        if(state == 0xffff){
            fclose(fp);
            exit(0);
        }
    }
}