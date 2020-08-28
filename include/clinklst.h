#ifndef _CLINKLST_H_
#define _CLINKLST_H_

#ifdef __cplusplus
extern "C" {
#endif
#if 0
}
#endif

#include <stdlib.h>

/*
 * ensure 'expr' has the same type as 'ref', 'expr' may be evaluated,
 * while 'ref' is never evaluated.
 */
#define CL_WITH_TYPE_OF(expr, ref)			\
  (1 ? (expr) : (ref))

#define CL_WITH_TYPE(expr, type)		\
  CL_WITH_TYPE_OF(expr, (type)0)

#define CL_CONTAINER_OF(mptr, type, member)			\
  (type*)((char*)CL_WITH_TYPE_OF(mptr, &((type*)0)->member)	\
	  - offsetof(type, member))

typedef struct cl_node {
  struct cl_node* next;
  struct cl_node** tous;
} cl_node;



#define CL_FOREACH(curp, firstp)					\
  for(CL_WITH_TYPE((curp = firstp), cl_node**);				\
      *curp; curp = &((*curp)->next))

#define CL_FOREACH_BACKWARD(curp, last, head)		\
  for(CL_WITH_TYPE((curp = &(last->next)), cl_node**);	\
      *curp != head; curp = ((cl_node*)curp)->tous)

void cl_insert_after(cl_node** curp, cl_node* newnode);
cl_node* cl_unlink_node(cl_node* node);

#if 0
{
#endif
#ifdef __cplusplus
}
#endif
#endif
