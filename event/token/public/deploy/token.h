#ifndef TOKEN_H
#define TOKEN_H

#include "vector.h"
extern char Global_Buffer[0x100];
extern uint64_t Global_Security_Token;
typedef struct {
  uint64_t Public_Token;
  uint64_t Private_Token;
  char Name[0x20];
  char Password[0x20];
} Token, *PToken;

void Safe_Input(char *buffer, size_t size);

uint64_t Security_Token_Gen(PToken Token);
void Security_Token_Check(PToken Token);

void Token_Create_Handler();
void Token_Insert_Handler();
void Token_Remove_Handler();
void Token_Display_Handler();
void Token_Edit_Handler();
void Token_Encrypt_Handler(Token *Src_Token, Token *Dst_Token);
void Token_Decrypt_Handler(Token *Encrypted_Token, Token *Dst_Token);
void Token_Export_Handler();
void Token_Import_Handler();

#endif