#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
int uprobe_add(int a, int b) { return a + b; }

int main() {
  srand(time(NULL));
  while (1) {
    int a = rand() & 255;
    int b = rand() & 255;
    int c = uprobe_add(a, b);
    assert(a + b == c);
    // usleep(1); 
  }
}
