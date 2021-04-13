#include <ESP8266WiFi.h> //https://github.com/esp8266/Arduino
#include <ritos.h>
#include <DNSServer.h>
#include <ESP8266WebServer.h>
#include <WIFIManager.h>
#include <string.h>
#define MSG_SIZE 10
#define _HC_ '\n'
#define Print false
#define PAYLOADLEN 200
/*RSAUtils*/
typedef struct
{
  int publicKey;
  int commonKey;
  int encryptBlockBytes;
} RSAKey;

/*TCPstruct*/
typedef struct
{
  char opCode[3];
  char SeqNum[2];
  char payLoad[PAYLOADLEN]; //Max
} IotPacketInterface;

/*SCENE CMD*/
typedef struct
{
  int sce_class; //0 for ctrl other iot,1 for time ctrl self node
  unsigned int hash;
  int triggerClass;
  int triggerJudgement; //-1_<,0_=,2_1
  char triggerEvent[10];
  int Cmd2IotId;
  int devclass;
  char Cmd2IotCmd[10];
  char Cmd2IotDate[8];
  char Cmd2IotTime[10];
  int CmdGroup;
  int fromUserId;
} SCE_CMD;

/*value*/
char chipID[10];
char SerialRecvBuf[10];
volatile boolean isConnected = false;
volatile boolean isRsaGet = false;
volatile boolean IsRsaGet = false;
volatile boolean isPinGet = false;
volatile boolean isRegAndSign = false;
volatile boolean IsRegAndSign = false;
volatile int key_state = 0;
char pin[7] = "";
WiFiClient cln;
Ritos threadExeMsg;
Ritos threadExeTask;
Ritos threadExeSerial;
char HBATime[20];
RSAKey rsaKey;
SCE_CMD sce_cmd;
char weekday[8];
float temperature = 0;
volatile int ErrCnt = 0;
volatile float LightStrength = 0;
/*IotMsgCacheList*/
typedef struct
{
  IotPacketInterface pack;
  /* data */
} MSG;
typedef struct
{
  volatile int len;
} MSG_HEAD;
MSG_HEAD msg_head;
MSG msg[MSG_SIZE];
/*func declaration*/
void encodeMessage(int len, int bytes, char *message, int *outCrypto, int exponent, int modulus);
void decodeMessage(int len, int bytes, int *cryptogram, char *outSource, int exponent, int modulus);
boolean Connect2Server();
int Stringcut(char *, int, int, char *);
void releaseStr(char **StrVector, int size);
char **StrSplit(char *srcStr, int srcStrLen, int *outBufferLen, char delim);
void Encrypt(char *source_in, int len, char *PinCode, char *source_out);
void Decrypt(char *source_in, int len, char *PinCode, char *source_out);
void PeriodTask();
void RecvFromSerial();
void Serialsend(char opcode, char *str);
void GetIotCmd(int devclass);
void GetIotData(char *str);
unsigned int DJBHash(char *str, unsigned int len);
void GetSceCmd();
void CheckSceCmd(int range);
const char *getWeekdayByYearday(int iY, int iM, int iD);
void onKeyEvent(); //-1 down , 0 nothing , 1 up
void Send9Server();
void Send8Server();
void Send4Server_LightStrength(float strength);
void Send4Server_D6_status();
void InitRsaAndPin();
void REGANDSIGN();
///*******
void resetValue()
{
  isConnected = false;
  isRsaGet = false;
  isPinGet = false;
  isRegAndSign = false;
  IsRsaGet = false;
}
boolean addMSG2CACHELIST(IotPacketInterface *pack)
{
  if (msg_head.len < MSG_SIZE)
  {
    memcpy(&(msg[msg_head.len].pack), pack, sizeof(IotPacketInterface));
    msg_head.len++;
    return true;
  }
  else
    return false;
}
void threadExeMSG()
{
  if (msg_head.len == 0)
    return;
  switch (atoi(msg[msg_head.len - 1].pack.opCode))
  {
  case 0:
  {
    Decrypt(msg[msg_head.len - 1].pack.payLoad, strlen(msg[msg_head.len - 1].pack.payLoad), pin, msg[msg_head.len - 1].pack.payLoad);
    int OutStrSize = 0;
    char **outStr = StrSplit(msg[msg_head.len - 1].pack.payLoad, PAYLOADLEN, &OutStrSize, '_');
    if (OutStrSize != 2)
    {
      releaseStr(outStr, OutStrSize);
      break;
    }
    switch (atoi(outStr[0]))
    {
    case 0:
    {
      Serialsend('0', outStr[1]);
      digitalWrite(D6, atoi(outStr[1]));
    }
    break;
    case 1:
      Serialsend('1', outStr[2]);
      break;
    default:
      break;
    }
    releaseStr(outStr, OutStrSize);
  }
  break;
  case 1:
  {
    int OutStrSize = 0;
    char **outStr = StrSplit(msg[msg_head.len - 1].pack.payLoad, PAYLOADLEN, &OutStrSize, '_');
    if (OutStrSize != 3)
    {
      isRsaGet = false;
      IsRsaGet = false;
      releaseStr(outStr, OutStrSize);
      break;
    }
    rsaKey.publicKey = atoi(outStr[0]);
    rsaKey.commonKey = atoi(outStr[1]);
    rsaKey.encryptBlockBytes = atoi(outStr[2]);
    releaseStr(outStr, OutStrSize);
    IsRsaGet = true;
  }
  break;
  case 2:
  {
    if (!IsRsaGet || rsaKey.encryptBlockBytes == 0)
    {
      msg_head.len++;
      break;
    }
    int OutStrSize = 0;
    char **outStr = StrSplit(msg[msg_head.len - 1].pack.payLoad, PAYLOADLEN, &OutStrSize, '_');
    if (OutStrSize != 1)
    {
      isPinGet = false;
      releaseStr(outStr, OutStrSize);
      break;
    }
    //MD5check???LOST//
    int encodedCrypto[100] = {0};
    memcpy(encodedCrypto, outStr[0], sizeof(int) * 6 * rsaKey.encryptBlockBytes);
    decodeMessage(6, rsaKey.encryptBlockBytes, encodedCrypto, pin, rsaKey.publicKey, rsaKey.commonKey);
    pin[6] = 0;
    releaseStr(outStr, OutStrSize);
    isPinGet = true;
  }
  break;
  case 3:
  {
    IsRegAndSign = true;
  }
  break;
  case 23:
  {
    IsRegAndSign = false;
    isRegAndSign = false;
    isRsaGet = false;
    IsRsaGet = false;
    isPinGet = false;
  }
  break;
  case 5:
  {
    Decrypt(msg[msg_head.len - 1].pack.payLoad, strlen(msg[msg_head.len - 1].pack.payLoad), pin, msg[msg_head.len - 1].pack.payLoad);
    int OutStrSize = 0;
    char **outStr = StrSplit(msg[msg_head.len - 1].pack.payLoad, PAYLOADLEN, &OutStrSize, '_');
    if (OutStrSize != 5)
    {
      releaseStr(outStr, OutStrSize);
      break; ///
    }
    switch (atoi(outStr[0]))
    {
    case 0:
    {
      Serialsend('0', outStr[1]);
      digitalWrite(D6, atoi(outStr[1]));
    }
    break;
    case 1:
      Serialsend('1', outStr[2]);
      break;
    default:
      break;
    }
    releaseStr(outStr, OutStrSize);
  }
  break;
  case 25:
  {
    //Serialsend('M', "NO MORE CMD AT NOW");
  }
  break;
  case 7:
  {
    Decrypt(msg[msg_head.len - 1].pack.payLoad, strlen(msg[msg_head.len - 1].pack.payLoad), pin, msg[msg_head.len - 1].pack.payLoad);
    int OutStrSize = 0;
    char **outStr = StrSplit(msg[msg_head.len - 1].pack.payLoad, PAYLOADLEN, &OutStrSize, '_');
    if (OutStrSize != 5)
    {
      releaseStr(outStr, OutStrSize);
      break; ///
    }
    ///*******
    releaseStr(outStr, OutStrSize);
  }
  break;
  case 6:
  {
    Decrypt(msg[msg_head.len - 1].pack.payLoad, strlen(msg[msg_head.len - 1].pack.payLoad), pin, msg[msg_head.len - 1].pack.payLoad);
    unsigned int cmd_hash = DJBHash(msg[msg_head.len - 1].pack.payLoad, strlen(msg[msg_head.len - 1].pack.payLoad));
    if (sce_cmd.hash == cmd_hash)
    {
      break;
    }
    int OutStrSize = 0;
    char **outStr = StrSplit(msg[msg_head.len - 1].pack.payLoad, PAYLOADLEN, &OutStrSize, '_');
    if (OutStrSize != 7)
    {
      releaseStr(outStr, OutStrSize);
      break; ///
    }
    sce_cmd.hash = cmd_hash;
    sce_cmd.triggerClass = atoi(outStr[0]);
    memcpy(sce_cmd.Cmd2IotDate, outStr[4], strlen(outStr[4]));
    memcpy(sce_cmd.Cmd2IotTime, outStr[3], strlen(outStr[3]));
    int OutStrSize1 = 0;
    char **outStr1 = StrSplit(outStr[1], strlen(outStr[1]), &OutStrSize1, '-');
    if (OutStrSize1 != 6)
    {
      if (OutStrSize1 != 3)
      {
        memset(&sce_cmd, 0, sizeof(SCE_CMD));
        releaseStr(outStr1, OutStrSize1);
        releaseStr(outStr, OutStrSize);
        break;
      }
      else
      {
        sce_cmd.sce_class = 0;
        sce_cmd.Cmd2IotId = atoi(outStr1[0]);
        sce_cmd.devclass = atoi(outStr1[1]);
        memcpy(sce_cmd.Cmd2IotCmd, outStr1[2], strlen(outStr1[2]));
        sce_cmd.CmdGroup = atoi(outStr[5]);
        sce_cmd.fromUserId = atoi(outStr[6]);
        releaseStr(outStr1, OutStrSize1);
        releaseStr(outStr, OutStrSize);
        break;
      }
    }
    sce_cmd.sce_class = 1;
    sce_cmd.Cmd2IotId = atoi(outStr1[3]);
    sce_cmd.devclass = atoi(outStr1[4]);
    memcpy(sce_cmd.Cmd2IotCmd, outStr1[5], strlen(outStr1[5]));
    sce_cmd.triggerJudgement = (outStr1[2][0] == '<') ? -1 : (outStr1[2][0] == '=' ? 0 : 1);
    Stringcut(outStr1[2], 1, strlen(outStr1[2]), sce_cmd.triggerEvent);
    releaseStr(outStr1, OutStrSize1);
    sce_cmd.CmdGroup = atoi(outStr[5]);
    sce_cmd.fromUserId = atoi(outStr[6]);
    ///*******
    releaseStr(outStr, OutStrSize);
  }
  break;
  default:
    break;
  }
  msg_head.len--;
}

boolean Connect2Server()
{
  if (isConnected)
  {
    return true;
  }
  //if (cln.connect("192.168.2.101", 3566))
  if (cln.connect("47.106.207.241", 3570))
  {
    isConnected = true;
    return true;
  }
  isConnected = false;
  return false;
}

void recvFromServer()
{
  char recvBuf[sizeof(IotPacketInterface)] = "";
  IotPacketInterface recvStruct;
  int len = 0;
  while (true)
  {
    len = cln.readBytesUntil(_HC_, recvBuf, sizeof(IotPacketInterface));
    if (len > 0)
    {
      if (recvBuf[0] == 'H')
      {
        Stringcut(recvBuf, 3, 21, HBATime);
        //RecvFromSerial();
        continue;
      }
      memset(&recvStruct, 0, sizeof(IotPacketInterface));
      memcpy(&recvStruct, recvBuf, len);
      if (!addMSG2CACHELIST(&recvStruct))
      {
        //resetValue();
        //Connect2Server();
      }
    }
    // else
    // {
    //   Serialsend('M', "RECV_FROM_SERVER_ERR");
    //   ErrCnt++;
    //   resetValue();
    // }
  }
}

void setup()
{
  Serial.begin(9600);
  memset(weekday, 0, 8);
  pinMode(D6, OUTPUT);
  digitalWrite(D6, 0);
  WiFiManager wifiManager;
  wifiManager.setTimeout(180);
  itoa(ESP.getFlashChipId(), chipID, 10);
  char WIFISSID[25] = "uubang_switch_";
  char chipSSID[8];
  itoa(ESP.getChipId(), chipSSID, 10);
  strcat(WIFISSID, chipSSID);
  if (!wifiManager.autoConnect(WIFISSID))
  {
    if (Print)
      Serial.println("[SET]failed to connect and hit timeout");
    delay(3000);
    ESP.reset();
    delay(5000);
  }
  if (Print)
    Serial.println("[SET]connected to wifi");
  msg_head.len = 0;
  Connect2Server();
  Serialsend('M', chipSSID);
  threadExeMsg.task(threadExeMSG);
  threadExeTask.task(PeriodTask);
}

void loop()
{
  // put your main code here, to run repeatedly:
  recvFromServer();
}

void PeriodTask()
{
  static char LastTime[20];
  static volatile long timer = 0;
  InitRsaAndPin();
  REGANDSIGN();
  timer++;
  if (timer % 1000 == 0)
  {
    LightStrength = analogRead(A0) / 10.24;
  }
  if (timer % 4000 == 0)
  {
    CheckSceCmd(5);
  }
  if (timer % 5000 == 0)
  {
    GetIotCmd(0);
    Send4Server_LightStrength(LightStrength);
    Send4Server_D6_status();
    if (ErrCnt > 10)
    {
      Connect2Server();
    }
    if (ErrCnt > 13)
    {
      ESP.restart();
    }
  }
  if (timer % 8000 == 0)
  {
    GetSceCmd();
    if (!strcmp(HBATime, LastTime))
    {
      Serialsend('E', "SYNC_TIME_ERR");
      ErrCnt++;
    }
    else
    {
      memcpy(LastTime, HBATime, sizeof(char) * 20);
    }
  }
  if (timer > 10000)
  {
    timer = 0;
  }
}

void Serialsend(char opcode, char *str)
{
  Serial.printf_P("_");
  Serial.print((char)(strlen(str) + 1));
  Serial.print(opcode);
  Serial.printf_P(str);
}

void CheckSceCmd(int range)
{
  if (sce_cmd.hash == 0)
    return;
  int y = HBATime[0] * 1000 + HBATime[1] * 100 + HBATime[2] * 10 + HBATime[3];
  int m = HBATime[5] * 10 + HBATime[6];
  int d = HBATime[8] * 10 + HBATime[9];
  memcpy(weekday, getWeekdayByYearday(y, m, d), 7);
  boolean flag = false;
  for (int i = 0; i < 7; i++)
  {
    if (weekday[i] + sce_cmd.Cmd2IotDate[i] == 2 * '1')
    {
      flag = true;
      break;
    }
    else
    {
      flag = false;
    }
  }
  if (!flag)
    return;
  if (sce_cmd.sce_class == 0)
  {
    int h = (HBATime[11] - sce_cmd.Cmd2IotTime[0]) * 10 + HBATime[12] - sce_cmd.Cmd2IotTime[1];
    int m = (HBATime[14] - sce_cmd.Cmd2IotTime[3]) * 10 + HBATime[15] - sce_cmd.Cmd2IotTime[4];
    int s = (HBATime[17] - sce_cmd.Cmd2IotTime[6]) * 10 + HBATime[18] - sce_cmd.Cmd2IotTime[7];
    if (h == 0 && m == 0 && abs(s) < range)
    {
      switch (sce_cmd.devclass)
      {
      case 0:
      {
        Serialsend('0', sce_cmd.Cmd2IotCmd);
        digitalWrite(D6, atoi(sce_cmd.Cmd2IotCmd));
      }
      break;
      case 1:
        Serialsend('1', sce_cmd.Cmd2IotCmd);
        break;
      default:
        break;
      }
    }
  }
  else
  {
    switch (sce_cmd.triggerClass)
    {
    case 0:
      if (sce_cmd.triggerJudgement == key_state) //-1 down  1 up
      {
        Send8Server();
        key_state = 0;
      }
      break;
    case 1:
    {
      static int isUpOrDown = 0; //-1 DOWN 1 UP
      static float LasttemperatureRec = 0;
      static boolean flag = false;
      if (!flag)
      {
        LasttemperatureRec = temperature;
        flag = true;
        break;
      }
      isUpOrDown = (LasttemperatureRec == temperature) ? 0 : (LasttemperatureRec > temperature ? -1 : 1);
      if (isUpOrDown == 0)
      {
        break;
      }
      if (sce_cmd.triggerJudgement == isUpOrDown)
      {
        switch (isUpOrDown)
        {
        case -1:
          if (temperature < atoi(sce_cmd.triggerEvent) + 1) //temperature tolerance 1
          {
            Send9Server();
          }
          break;
        case 1:
          if (temperature > atoi(sce_cmd.triggerEvent) - 1) //temperature tolerance 1
          {
            Send9Server();
          }
          break;
        default:
          break;
        }
      }
      LasttemperatureRec = temperature;
    }
    break;
    case 3:
    {
      static int isUpOrDown = 0; //-1 DOWN 1 UP
      static float LastLightStrRec = 0;
      static boolean flag = false;
      if (!flag)
      {
        LastLightStrRec = LightStrength;
        flag = true;
        break;
      }
      isUpOrDown = (LastLightStrRec == LightStrength) ? 0 : (LastLightStrRec > LightStrength ? -1 : 1);
      if (isUpOrDown == 0)
      {
        break;
      }
      if (sce_cmd.triggerJudgement == isUpOrDown)
      {
        switch (isUpOrDown)
        {
        case -1:
          if (LightStrength < atoi(sce_cmd.triggerEvent) + 5) //LastLightStrRec tolerance 5
          {
            Send8Server();
          }
          break;
        case 1:
          if (LightStrength > atoi(sce_cmd.triggerEvent) - 5) //LastLightStrRec tolerance 5
          {
            Send8Server();
          }
          break;
        default:
          break;
        }
      }
      LastLightStrRec = LightStrength;
    }
    default:
      break;
    }
  }
}

void RecvFromSerial()
{
  char recv[30];
  Serial.setTimeout(50);
  int len = Serial.readBytesUntil('_', recv, 30);
  if (len == 0)
  {
    return;
  }
  IotPacketInterface tmp;
  memset(&tmp, 0, sizeof(IotPacketInterface));
  switch (recv[0])
  {
  case '0': //update_status
  {
    char tmpbuf[11];
    tmp.opCode[0] = '0';
    tmp.opCode[1] = '4';
    sprintf(tmp.payLoad, "0_%d_", (recv[1] == '0' ? 0 : 1));
    Encrypt(tmp.payLoad, strlen(tmp.payLoad), pin, tmp.payLoad);
    memcpy(tmpbuf, &tmp, 11);
    cln.write_P(tmpbuf, 11);
    cln.flush(50);
  }
  break;
  case '1': //update_temperature
  {
    char tmpbuf[20];
    tmp.opCode[0] = '0';
    tmp.opCode[1] = '4';
    if (recv[3] == 0)
      recv[3] = '0';
    float tem = (float)(recv[1] - 48) + (float)(recv[2] - 48) / 10 + (float)(recv[3] - 48) / 100;
    sprintf(tmp.payLoad, "1_%.2f_", tem);
    Encrypt(tmp.payLoad, strlen(tmp.payLoad), pin, tmp.payLoad);
    memcpy(tmpbuf, &tmp, 20);
    cln.write_P(tmpbuf, 20);
    cln.flush(50);
  }
  break;
  case 'A': //get_status_cmd
  {
    GetIotCmd(0); //switch
  }
  break;
  case 'B': //get_temperature_cmd
  {
    GetIotCmd(1); //temp
  }
  break;
  case 'F': //get_scene_cmd
  {
    GetSceCmd(); //scene
  }
  case 'G': //set_temperature_cmd
  {
    temperature = recv[1];
  }
  break;
  case 'H': //set_keyState_cmd
  {
    key_state = (recv[1] == 'U') ? 1 : -1;
  }
  break;
  default:
    break;
  }
  return;
}

void GetIotCmd(int devclass)
{
  IotPacketInterface tmp;
  memset(&tmp, 0, sizeof(IotPacketInterface));
  char tmpbuf[11];
  tmp.opCode[0] = '0';
  tmp.opCode[1] = '5';
  sprintf(tmp.payLoad, "%d_", devclass);
  Encrypt(tmp.payLoad, strlen(tmp.payLoad), pin, tmp.payLoad);
  memcpy(tmpbuf, &tmp, 11);
  int len = cln.write_P(tmpbuf, 11);
  if (len == 0)
  {
    ErrCnt++;
  }
  cln.flush(50);
}

void GetSceCmd()
{
  IotPacketInterface tmp;
  memset(&tmp, 0, sizeof(IotPacketInterface));
  char tmpbuf[11];
  tmp.opCode[0] = '0';
  tmp.opCode[1] = '6';
  memcpy(tmpbuf, &tmp, 11);
  int len = cln.write_P(tmpbuf, 11);
  if (len == 0)
  {
    ErrCnt++;
  }
  cln.flush(50);
}

void GetIotData(char *str)
{
  if (strlen(str) > 20)
    return;
  ///str = "id1_id2_id3_... len<30-1-5=24
  IotPacketInterface tmp;
  memset(&tmp, 0, sizeof(IotPacketInterface));
  char tmpbuf[30];
  tmp.opCode[0] = '0';
  tmp.opCode[1] = '7';
  sprintf(tmp.payLoad, "%s", str);
  Encrypt(tmp.payLoad, strlen(tmp.payLoad), pin, tmp.payLoad);
  memcpy(tmpbuf, &tmp, 30);
  int len = cln.write_P(tmpbuf, 30);
  if (len == 0)
  {
    ErrCnt++;
  }
  cln.flush(50);
}

void Send9Server()
{
  IotPacketInterface tmp;
  memset(&tmp, 0, sizeof(IotPacketInterface));
  char tmpbuf[30];
  tmp.opCode[0] = '0';
  tmp.opCode[1] = '9';
  sprintf(tmp.payLoad, "%d_%d_%s_", sce_cmd.Cmd2IotId, sce_cmd.devclass, sce_cmd.Cmd2IotCmd);
  Encrypt(tmp.payLoad, strlen(tmp.payLoad), pin, tmp.payLoad);
  memcpy(tmpbuf, &tmp, 30);
  int len = cln.write_P(tmpbuf, 30);
  if (len == 0)
  {
    ErrCnt++;
  }
  cln.flush(50);
}

void Send8Server()
{
  IotPacketInterface tmp;
  memset(&tmp, 0, sizeof(IotPacketInterface));
  char tmpbuf[30];
  tmp.opCode[0] = '0';
  tmp.opCode[1] = '8';
  sprintf(tmp.payLoad, "%d_%d_%s_", sce_cmd.Cmd2IotId, sce_cmd.devclass, sce_cmd.Cmd2IotCmd);
  Encrypt(tmp.payLoad, strlen(tmp.payLoad), pin, tmp.payLoad);
  memcpy(tmpbuf, &tmp, 30);
  int len = cln.write_P(tmpbuf, 30);
  if (len == 0)
  {
    ErrCnt++;
  }
  cln.flush(50);
}

void Send4Server_LightStrength(float strength)
{
  IotPacketInterface tmp;
  memset(&tmp, 0, sizeof(IotPacketInterface));
  char tmpbuf[30];
  tmp.opCode[0] = '0';
  tmp.opCode[1] = '4';
  sprintf(tmp.payLoad, "3_%.2f_", strength); //brightness
  Encrypt(tmp.payLoad, strlen(tmp.payLoad), pin, tmp.payLoad);
  memcpy(tmpbuf, &tmp, 30);
  int len = cln.write_P(tmpbuf, 30);
  if (len == 0)
  {
    ErrCnt++;
  }
  cln.flush(50);
}

void Send4Server_D6_status()
{
  IotPacketInterface tmp;
  memset(&tmp, 0, sizeof(IotPacketInterface));
  char tmpbuf[11];
  tmp.opCode[0] = '0';
  tmp.opCode[1] = '4';
  sprintf(tmp.payLoad, "0_%d_", digitalRead(D6));
  Encrypt(tmp.payLoad, strlen(tmp.payLoad), pin, tmp.payLoad);
  memcpy(tmpbuf, &tmp, 11);
  int len = cln.write_P(tmpbuf, 11);
  if (len == 0)
  {
    ErrCnt++;
  }
  cln.flush(50);
}

void InitRsaAndPin()
{
  if (!isConnected)
    return;
  if (!isRsaGet)
  {
    IotPacketInterface tmp;
    memset(&tmp, 0, sizeof(IotPacketInterface));
    char tmpbuf[11];
    tmp.opCode[0] = '0';
    tmp.opCode[1] = '1';
    memcpy(tmpbuf, &tmp, 11);
    if (cln.write_P(tmpbuf, 11) == 0)
    {
      resetValue();
      if (Print)
        Serial.println("[RSA]Lost conn with  server");
      return;
    }
    isRsaGet = true;
  }
  if (!isPinGet && IsRsaGet)
  {
    IotPacketInterface tmp;
    memset(&tmp, 0, sizeof(IotPacketInterface));
    char tmpbuf[11];
    tmp.opCode[0] = '0';
    tmp.opCode[1] = '2';
    memcpy(tmpbuf, &tmp, 11);
    if (cln.write_P(tmpbuf, 11) == 0)
    {
      resetValue();
      if (Print)
        Serial.println("[PIN]Lost conn with  server");
      return;
    }
    isPinGet = true;
  }
}

void REGANDSIGN()
{
  if (isRegAndSign || !isConnected || !IsRsaGet)
    return;
  IotPacketInterface tmp;
  memset(&tmp, 0, sizeof(IotPacketInterface));
  char tmpbuf[sizeof(IotPacketInterface)];
  tmp.opCode[0] = '0';
  tmp.opCode[1] = '3';
  int encodedCrypto[50] = {0};
  char encodedCryptoByte[160];
  memset(encodedCryptoByte, 0, 160);
  encodeMessage(strlen(chipID) * rsaKey.encryptBlockBytes, rsaKey.encryptBlockBytes, chipID, encodedCrypto, rsaKey.publicKey, rsaKey.commonKey);
  memcpy(encodedCryptoByte, encodedCrypto, strlen(chipID) * rsaKey.encryptBlockBytes * 4);
  sprintf(tmp.payLoad, "%d_", ESP.getChipId());
  Stringcut(encodedCryptoByte, 0, strlen(chipID) * rsaKey.encryptBlockBytes * 4 - 1, tmp.payLoad + 8);
  tmp.payLoad[strlen(chipID) * rsaKey.encryptBlockBytes * 4 + 8] = '_';
  memcpy(tmpbuf, &tmp, sizeof(IotPacketInterface));
  if (cln.write_P(tmpbuf, sizeof(IotPacketInterface)) == 0)
  {
    resetValue();
    if (Print)
      Serial.println("[REG]Lost conn with  server");
    return;
  }
  isRegAndSign = true;
}