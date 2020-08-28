#include "clinklst.h"

void cl_insert_after(cl_node** curp, cl_node* newnode)
{
  newnode->next = *curp;
  if (*curp)
    (*curp)->tous = &(newnode->next);
  *curp = newnode;
  newnode->tous = curp;
}

cl_node* cl_unlink_node(cl_node* node)
{
  if (node->tous) {
    *(node->tous) = node->next;
    if (node->next) {
      node->next->tous = node->tous;
    }
  }
  return node;
}
