#include "main.h"

char Global_Buffer[0x100];
uint64_t Global_Security_Token;
PVector_Type Vector_Token;
int (*Before_Exit_Handlers)() = main;

void _EXIT(int status) {
  Before_Exit_Handlers();
  _exit(status);
}


void Set_Up() {
  Global_Security_Token = (uint64_t)rand() << 32 | rand(); // Random for fun
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
  Vector_Token = Vector_Init();
}

void Menu() {
  puts("Welcome to the Token Manager!");
  puts("1. Create Token");
  puts("2. Insert Token");
  puts("3. Remove Token");
  puts("4. Display Tokens");
  puts("5. Edit Token");
  puts("6. Export Token");
  puts("7. Import Token");
  puts("8. Exit");
  printf("Enter your choice: ");
}

int main() {
  Set_Up();
  while (1) {
    Menu();
    Safe_Input(Global_Buffer, sizeof(Global_Buffer));
    switch (atoi(Global_Buffer)) {
    case 1:
      Token_Create_Handler();
      break;
    case 2:
      Token_Insert_Handler();
      break;
    case 3:
      Token_Remove_Handler();
      break;
    case 4:
      Token_Display_Handler();
      break;
    case 5:
      Token_Edit_Handler();
      break;
    case 6:
      Token_Export_Handler();
      break;
    case 7:
      Token_Import_Handler();
      break;
    case 8:
      _EXIT(0);
      break;
    default:
      puts("Invalid choice!");
    }
  }
}