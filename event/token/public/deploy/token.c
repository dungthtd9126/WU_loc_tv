#include "token.h"

void Safe_Input(char *Buffer, size_t Size) {
  int Num = 0;
  for (size_t i = 0; i < Size - 1; i++) {
    Num = read(0, &Buffer[i], 1);
    if (Num <= 0) {
      Buffer[0] = '\0';
      return;
    }
    if (Buffer[i] == '\n') {
      return;
    }
  }
  Buffer[Size-1] = '\0';
  return;
}

uint64_t Security_Public_Token_Gen(PToken Token) {
  return ((uintptr_t)&Token->Public_Token >> 12) ^ ((uintptr_t)&Global_Security_Token); // For Checking Security Token
}

uint64_t Security_Private_Token_Gen(PToken Token) {
  return ((uintptr_t)&Global_Security_Token) ^ ((uintptr_t)Global_Security_Token >> 12); // For Checking Security Token
}

void Security_Token_Check(PToken Token) {
  if (Token->Private_Token != Security_Private_Token_Gen(Token)) {
    puts("Invalid security token!");
    _exit(1);
  }
}

void Token_Create_Handler() {
  PToken New_Token = (PToken)malloc(sizeof(Token));
  if (New_Token == NULL) {
    puts("Memory allocation failed!");
    return;
  }
  printf("Enter name: ");
  Safe_Input(New_Token->Name, 0x20);
  printf("Enter password: ");
  Safe_Input(New_Token->Password, 0x20);
  New_Token->Private_Token = Security_Private_Token_Gen(New_Token);
  New_Token->Public_Token = Security_Public_Token_Gen(New_Token);
  Vector_Token = Vector_Add(Vector_Token, New_Token);
}

void Token_Insert_Handler() {
  printf("Enter index to insert: ");
  Safe_Input(Global_Buffer, sizeof(Global_Buffer));
  size_t Index = atoi(Global_Buffer);
  PToken New_Token = (PToken)malloc(sizeof(Token));
  if (New_Token == NULL) {
    puts("Memory allocation failed!");
    return;
  }
  printf("Enter name: ");
  Safe_Input(New_Token->Name, 0x20);
  printf("Enter password: ");
  Safe_Input(New_Token->Password, 0x20);
  New_Token->Private_Token = Security_Private_Token_Gen(New_Token);
  New_Token->Public_Token = Security_Public_Token_Gen(New_Token);
  Vector_Token = Vector_Insert(Vector_Token, Index, New_Token);
}

void Token_Remove_Handler() {
  printf("Enter index to remove: ");
  Safe_Input(Global_Buffer, sizeof(Global_Buffer));
  size_t Index = atoi(Global_Buffer);
  Security_Token_Check(*(void **)(Vector_Token->vector_head + Index * sizeof(void *)));
  Vector_Token = Vector_Remove(Vector_Token, Index);
}

void Token_Display_Handler() {
  size_t Index = 0;
  PToken Current_Token = NULL;
  while ((Current_Token = (PToken)Vector_Get(Vector_Token, Index)) != NULL) {
    Security_Token_Check(Current_Token);
    printf("Index %zu: Name: %s, Password: %s\n", Index, Current_Token->Name,
           Current_Token->Password);
    Index++;
  }
}

void Token_Edit_Handler() {
  printf("Enter index to edit: ");
  Safe_Input(Global_Buffer, sizeof(Global_Buffer));
  size_t Index = atoi(Global_Buffer);
  PToken Token = (PToken)Vector_Get(Vector_Token, Index);
  if (Token == NULL) {
    puts("Invalid index!");
    return;
  }
  Security_Token_Check(Token);
  printf("Enter new name: ");
  Safe_Input(Token->Name, 0x20);
  printf("Enter new password: ");
  Safe_Input(Token->Password, 0x20);
}

void Token_Encrypt_Handler(Token *Src_Token, Token *Dst_Token)
{
  memset(Dst_Token, 0, sizeof(Token));
  uint64_t* Enc_Name_Block = (uint64_t*)Dst_Token->Name;
  uint64_t* Enc_Pass_Block = (uint64_t*)Dst_Token->Password;
  uint64_t* Dec_Name_Block = (uint64_t*)Src_Token->Name;
  uint64_t* Dec_Pass_Block = (uint64_t*)Src_Token->Password;

  for (size_t i = 0; i < 4; i++) {
    Enc_Name_Block[i] = Dec_Name_Block[i] ^ Src_Token->Public_Token;
    Enc_Pass_Block[i] = Dec_Pass_Block[i] ^ Src_Token->Private_Token;
  }
  Dst_Token->Public_Token = Src_Token->Public_Token ^ Global_Security_Token;
  Dst_Token->Private_Token = Src_Token->Private_Token;
}

void Token_Decrypt_Handler(Token *Encrypted_Token, Token *Dst_Token)
{
  memset(Dst_Token, 0, sizeof(Token));
  uint64_t* Enc_Name_Block = (uint64_t*)Encrypted_Token->Name;
  uint64_t* Enc_Pass_Block = (uint64_t*)Encrypted_Token->Password;
  uint64_t* Dec_Name_Block = (uint64_t*)Dst_Token->Name;
  uint64_t* Dec_Pass_Block = (uint64_t*)Dst_Token->Password;

  Dst_Token->Public_Token = Encrypted_Token->Public_Token ^ Global_Security_Token;
  for (size_t i = 0; i < 4; i++) {
    Dec_Name_Block[i] = Enc_Name_Block[i] ^ Dst_Token->Public_Token;
    Dec_Pass_Block[i] = Enc_Pass_Block[i] ^ Dst_Token->Private_Token;
  }
}

void Token_Export_Handler()
{
  printf("Enter index to export: ");
  Safe_Input(Global_Buffer, sizeof(Global_Buffer));
  size_t Index = atoi(Global_Buffer);

  PToken Cur_Token = (PToken)Vector_Get(Vector_Token, Index);
  if (Cur_Token == NULL) {
    puts("Invalid index!");
    return;
  }
  Security_Token_Check(Cur_Token);
  
  Token Encrypted_Token;
  memset(&Encrypted_Token, 0, sizeof(Token));
  Token_Encrypt_Handler(Cur_Token, &Encrypted_Token);

  printf("Exported Token: \n Name:           ");
  for (int i = 0; i < 0x20; i++) {
    printf("%02X", (unsigned char)Encrypted_Token.Name[i]);
  }
  printf("\n Password:       ");
  for (int i = 0; i < 0x20; i++) {
    printf("%02X", (unsigned char)Encrypted_Token.Password[i]);
  }
  printf("\n Security Token: %lu\n", Encrypted_Token.Public_Token);
  printf("\n Private Token: %lu\n", Encrypted_Token.Private_Token);
}

void Token_Import_Handler()
{
  printf("Enter token to import (Format: Hex_Name:Hex_Password:Security_Token): ");
  Safe_Input(Global_Buffer, sizeof(Global_Buffer));

  char *Delim1 = strchr(Global_Buffer, ':');
  if (Delim1 == NULL) { puts("Invalid format!"); return; }
  *Delim1 = '\0';

  char *Delim2 = strchr(Delim1 + 1, ':');
  if (Delim2 == NULL) { puts("Invalid format!"); return; }
  *Delim2 = '\0';

  char *NameHex = Global_Buffer;
  char *PasswordHex = Delim1 + 1;
  char *SecTokenStr = Delim2 + 1;

  if (strlen(NameHex) < 64 || strlen(PasswordHex) < 64) {
    puts("Invalid token data length!");
    return;
  }

  Token Encrypted_Token;
  memset(&Encrypted_Token, 0, sizeof(Token));

  for (int i = 0; i < 0x20; i++) {
    sscanf(NameHex + (i * 2), "%2hhx", &Encrypted_Token.Name[i]);
    sscanf(PasswordHex + (i * 2), "%2hhx", &Encrypted_Token.Password[i]);
  }

  char *EndPtr;
  unsigned long long Parsed_SecToken = strtoull(SecTokenStr, &EndPtr, 0); 
  if (EndPtr == SecTokenStr) {
      puts("Security Token cannot be empty or invalid!");
      return;
  }
  if (*EndPtr != '\0' && *EndPtr != '\n') {
      puts("Invalid characters in Security Token!");
      return;
  }
  
  Encrypted_Token.Public_Token = (uint64_t)Parsed_SecToken;

  printf("Select slot to import (must be the existing one): ");
  Safe_Input(Global_Buffer, sizeof(Global_Buffer));
  size_t Index = atoi(Global_Buffer);
  PToken New_Token = (PToken)Vector_Get(Vector_Token, Index);
  if (New_Token == NULL) return;
  Token_Decrypt_Handler(&Encrypted_Token, New_Token);
  New_Token->Private_Token = Security_Private_Token_Gen(New_Token);
  Security_Token_Check(New_Token);
  puts("Token imported successfully!");
}