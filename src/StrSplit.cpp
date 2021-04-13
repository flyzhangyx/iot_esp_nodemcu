#define NULL 0
extern "C"
{
#include "user_interface.h"
}

int Stringcut(char *str, int m, int n, char *des)
{
  int i = m;
  for (; i <= n; i++)
  {
    des[i - m] = str[i];
  }
  des[i - m] = '\0';
  return 1;
}

char **StrSplit(char *srcStr, int srcStrLen, int *outBufferLen, char delim)
{
    int i = 0;
    int j = 0;
    int k = 0;
    int l = 0;
    int m = 0;
    char **outStr;
    while (i < srcStrLen)
    {
        if (srcStr[i] == delim)
        {
            j++;
        }
        i++;
    }
    outStr = (char **)malloc(sizeof(char *) * j);
    i = 0;
    while (i < srcStrLen)
    {
        if (srcStr[i] != delim)
        {
            k++;
        }
        else
        {
            outStr[l] = (char *)malloc(sizeof(char) * (k + 1));
            if (outStr[l] == NULL)
            {
                return NULL;
            }
            Stringcut(srcStr, m, i - 1, outStr[l]);
            m = i + 1;
            k = 0;
            l++;
        }
        i++;
    }
    *outBufferLen = j;
    return outStr;
}

void releaseStr(char **StrVector, int size)
{
    while (size--)
    {
        free(StrVector[size]);
    }
    free(StrVector);
}