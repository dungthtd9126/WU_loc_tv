#include <stdint.h>

typedef struct product product;
typedef struct cart_item cart_item;
typedef struct comment comment;

struct comment
{
    uint64_t len;
    char *content;
};

struct product
{
    char name[0x20];
    long long price;
    int purchase_count;
};

struct cart_item
{
    product *item;
    int quantity;             
    cart_item *next;
};

cart_item *cart_head = NULL;
comment *cmt[0x20] = {0};