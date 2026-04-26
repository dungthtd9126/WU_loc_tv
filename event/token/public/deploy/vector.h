#ifndef VECTOR_H
#define VECTOR_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define VECTOR_FAILURE NULL
#define VECTOR_OUT_OF_SPACE NULL
#define VECTOR_INVALID_INDEX NULL

typedef struct {
  void *vector_head;
  void *vector_bottom;  
  void *current;
} Vector_Type, *PVector_Type;

extern PVector_Type Vector_Token;

PVector_Type Vector_Init();
PVector_Type Vector_Add(PVector_Type vector, void *item);
void *Vector_Get(PVector_Type vector, size_t index);
PVector_Type Vector_Insert(PVector_Type vector, size_t index, void *item);
PVector_Type Vector_Remove(PVector_Type vector, size_t index);
PVector_Type Vector_Reinit(PVector_Type vector);

#endif