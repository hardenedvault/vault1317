/*
 * Copyright (C) 2018-2021, HardenedVault Limited (https://hardenedvault.net)
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

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
