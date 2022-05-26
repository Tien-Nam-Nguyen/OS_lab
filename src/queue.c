#include <stdio.h>
#include <stdlib.h>
#include "queue.h"

int empty(struct queue_t * q) {
	return (q->size == 0);
}

void enqueue(struct queue_t * q, struct pcb_t * proc) {
	/* TODO: put a new process to queue [q] */
	if(q->size < MAX_QUEUE_SIZE && q->size >= 0 && proc != NULL){
		for(int i = 0; i < MAX_QUEUE_SIZE; i++){
			if(q->proc[i] == NULL){
				q->proc[i] = proc;
				q->size++;
				break;
			}
		}
	}	
}

struct pcb_t * dequeue(struct queue_t * q) {
	/* TODO: return a pcb whose prioprity is the highest
	 * in the queue [q] and remember to remove it from q
	 * */
	if(q->size > 0){
		int k = -1;
	 	for(int i = 0; i < MAX_QUEUE_SIZE; i++){
			if(q->proc[i] != NULL && k == -1){
				k = i;
				continue;
			}
			if(q->proc[i] != NULL){
				if(q->proc[i]->priority >= q->proc[k]->priority){
					k = i;
				}
			}
			
		}
		struct pcb_t *res = q->proc[k];
		q->proc[k] = NULL;
		q->size--;
		return res;
	}
	else return NULL;
	
}

