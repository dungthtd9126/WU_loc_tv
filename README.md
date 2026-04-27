# Write up lọc thành viên
## cypher 
```
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char name[32]; // [rsp+0h] [rbp-C0h] BYREF
  int (__fastcall *func_ptr_1)(__int64, unsigned __int64); // [rsp+20h] [rbp-A0h]
  int (*shell_call)(); // [rsp+28h] [rbp-98h]
  _BYTE arr[140]; // [rsp+30h] [rbp-90h]
  int i; // [rsp+BCh] [rbp-4h]

  setup();
  puts("CipherBox Pro v3.1 - Byte Encoder\n");
  memset(name, 0, 0xB8u);
  printf("Name: ");
  readstr(name, 32);
  func_ptr_1 = print_hex;
  shell_call = session_done;
  for ( i = 0; i <= 127; ++i )
    arr[i] = i ^ 90;
  printf("[+] '%s' ready.\n\n", name);
  while ( 1 )
  {
    puts("[1]set [2]get [3]encode [4]reset [5]dump [0]quit");
    printf(">> ");
    switch ( readint() )
    {
      case 0:
        shell_call();                           // overwrite to be main -> bypass 0x10 alignment of system
        return 0;
      case 1:
        do_set((__int64)name);                  // oob write
...
```
- Bài này có bug khá rõ là oob ở do_set dẫn đến ghi đè function ptr. Em sẽ ghi đè exe.plt.system vào func_ptr_1 để có thể thực hiện system call
- Trước đó em sẽ set up chuỗi 'sh' bằng hàm do_set nhờ vào bug oob
```
int __fastcall do_set(__int64 ptr)
{
  unsigned int end; // [rsp+18h] [rbp-8h]
  unsigned int start; // [rsp+1Ch] [rbp-4h]

  printf("  From (0-255): ");
  start = readint();
  printf("  To   (0-255): ");
  end = readint();
  if ( start >= 0x100 || end >= 0x100 )
    return puts("  [-] Invalid byte value");
  set_mapping(ptr, start, end);
  return puts("  [+] Updated");
}
```
- Tiếp theo, gọi do_encode sao cho chương trình lấy đúng chuỗi 'sh' mà em đã thiết lập trước đó rồi gọi system mà em đã set up trước đó.
- Hàm này khá đặt biệt là nó sử dụng input của em như idx để lấy dữ liệu từ stack.
```
int __fastcall do_encode(__int64 ptr)
{
  char v2[256]; // [rsp+10h] [rbp-210h] BYREF
  char s[256]; // [rsp+110h] [rbp-110h] BYREF
  size_t len; // [rsp+210h] [rbp-10h]
  size_t i; // [rsp+218h] [rbp-8h]

  printf("  Text: ");
  readstr(s, 256);
  len = strlen(s);
  if ( !len )
    return puts("  [-] Empty input");
  for ( i = 0; i < len; ++i )
    v2[i] = *(_BYTE *)(ptr + (unsigned __int8)s[i] + 48);// getting arbitrary value from the stack
  v2[len] = 0;
  ++*(_DWORD *)(ptr + 176);
  printf("  [+] ");
  return (*(__int64 (__fastcall **)(char *, size_t))(ptr + 32))(v2, len);// call shell
}
```
## Store
- Bài này thì khá là khó ở chỗ code dài nên em bị đánh tâm lý khúc này. Challenge này có 1 bug chính, OOB write dẫn đến arbitrary read and write theo cách của em
- 
