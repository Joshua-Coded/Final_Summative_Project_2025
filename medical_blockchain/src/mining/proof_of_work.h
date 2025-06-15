#ifndef PROOF_OF_WORK_H
#define PROOF_OF_WORK_H

#include "../core/block.h"

#define DEFAULT_DIFFICULTY 2

int proof_of_work_mine_block(Block* block, int difficulty);
int proof_of_work_id_valid(const Block* block, int difficulty);

#endif
