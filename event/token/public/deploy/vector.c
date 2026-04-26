#include "vector.h"

PVector_Type Vector_Init() {
  PVector_Type vector = (PVector_Type)malloc(sizeof(Vector_Type));
  if (vector == NULL)
    return VECTOR_FAILURE;

  size_t initial_capacity = 0x10 * sizeof(void *);
  vector->vector_head = (char *)malloc(initial_capacity);
  if (vector->vector_head == NULL) {
    free(vector);
    return VECTOR_FAILURE;
  }

  vector->vector_bottom = vector->vector_head + initial_capacity;
  vector->current = vector->vector_head;
  return vector;
}

PVector_Type Vector_Add(PVector_Type vector, void *item) {
  if (vector->current >= vector->vector_bottom) {
    if (Vector_Reinit(vector) == VECTOR_FAILURE)
      return VECTOR_FAILURE;
  }

  *(void **)vector->current = item;
  vector->current += sizeof(void *);
  return vector;
}

void *Vector_Get(PVector_Type vector, size_t index) {
  size_t max_index = (vector->current - vector->vector_head) / sizeof(void *);
  if (index >= max_index)
    return NULL;

  return *(void **)(vector->vector_head + index * sizeof(void *));
}

PVector_Type Vector_Insert(PVector_Type vector, size_t index, void *item) {
  size_t current_count =
      (vector->current - vector->vector_head) / sizeof(void *);
  if (index > current_count)
    return VECTOR_INVALID_INDEX;
  if (vector->current >= vector->vector_bottom) {
    if (Vector_Reinit(vector) == VECTOR_FAILURE)
      return VECTOR_FAILURE;
  }

  for (size_t i = current_count; i > index; i--) {
    *(void **)(vector->vector_head + i * sizeof(void *)) =
        *(void **)(vector->vector_head + (i - 1) * sizeof(void *));
  }

  *(void **)(vector->vector_head + index * sizeof(void *)) = item;
  vector->current += sizeof(void *);
  return vector;
}

PVector_Type Vector_Remove(PVector_Type vector, size_t index) {
  size_t current_count =
      (vector->current - vector->vector_head) / sizeof(void *);
  if (index > current_count)
    return VECTOR_INVALID_INDEX;
  free(*(void **)(vector->vector_head + index * sizeof(void *)));
  for (size_t i = index; i < current_count - 1; i++) {
    *(void **)(vector->vector_head + i * sizeof(void *)) =
        *(void **)(vector->vector_head + (i + 1) * sizeof(void *));
  }
  vector->current -= sizeof(void *);
  return vector;
}

PVector_Type Vector_Reinit(PVector_Type vector) {
  size_t old_capacity = vector->vector_bottom - vector->vector_head;
  size_t old_size = vector->current - vector->vector_head;
  size_t new_capacity = old_capacity * 2;
  char *new_head = (char *)malloc(new_capacity);
  if (new_head == NULL)
    return VECTOR_FAILURE;

  memcpy(new_head, vector->vector_head, old_size);
  free(vector->vector_head);
  vector->vector_head = new_head;
  vector->vector_bottom = new_head + new_capacity;

  vector->current = new_head + old_size;

  return vector;
}