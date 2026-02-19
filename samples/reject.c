#include <sys/syscall.h>

int main(void) {
  volatile long sys_nr = 172;
  return syscall(sys_nr, 1, 2, 3, 4, 5, 6);
}
