#include "queue.h"
#include <stdio.h>
#include <stdlib.h>

int
empty (struct queue_t *q)
{
  return (q->size == 0);
}

void
enqueue (struct queue_t *q, struct pcb_t *proc)
{
  /* TODO: put a new process to queue [q] */
  if (q->size < MAX_QUEUE_SIZE && q->size >= 0 && proc != NULL)
    {
      q->proc[q->size] = proc;
      q->size++;
    }
}

struct pcb_t *
dequeue (struct queue_t *q)
{
  /* TODO: return a pcb whose prioprity is the highest
   * in the queue [q] and remember to remove it from q
   * */
  if (q->size > 0)
    {
      int k = -1;
      for (int i = 0; i < MAX_QUEUE_SIZE; i++)
        {
          if (q->proc[i] != NULL && k == -1)
            {
              k = i;
              continue;
            }
          if (q->proc[i] != NULL)
            {
              if (q->proc[i]->priority > q->proc[k]->priority)    //bo dau =
                {
                  k = i;
                }
            }
        }
      struct pcb_t *res = q->proc[k];
      q->proc[k] = NULL;
      for (int j = k; j < MAX_QUEUE_SIZE - 1; j++)
        {
          q->proc[j] = q->proc[j+1];
        }
      q->proc[q->size - 1] = NULL;
      q->size--;
      return res;
    }
  else
    return NULL;
}
