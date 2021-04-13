extern "C" {
  #include "user_interface.h"
}
void Encrypt(char *source_in ,int len,char *PinCode,char *source_out)
{
    int i = 0;
    while(i<len)
    {
        source_out[i] = source_in[i]+PinCode[i%6];
        i++;
    }
    return ;
}

void Decrypt(char *source_in ,int len,char *PinCode,char *source_out)
{
    int i = 0;
    while(i<len)
    {
        source_out[i] = source_in[i]-PinCode[i%6];
        i++;
    }
    return ;
}
