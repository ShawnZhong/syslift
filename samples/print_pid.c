#include <stdio.h>
#include <unistd.h>

int main(void) {
  pid_t pid = getpid();
  printf("pid: %d\n", pid);
  return pid == -ENOSYS;
}
